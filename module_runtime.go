package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2/v2"
	"github.com/dop251/goja"
)

func init() {
	regexp2.DefaultMatchTimeout = 250 * time.Millisecond
}

type scriptRuntime struct {
	mu             sync.Mutex
	programs       map[string]*goja.Program
	persistent     map[string]map[string]string
	statePath      string
	moduleSet      string
	moduleSetReady bool
	networkSlots   chan struct{}
}

type scriptMessage struct {
	URL        string
	Method     string
	Headers    http.Header
	Trailers   http.Header
	Body       []byte
	StatusCode int
}

type scriptResult struct {
	URL             string
	Headers         http.Header
	Trailers        http.Header
	Body            []byte
	StatusCode      int
	Synthetic       bool
	Abort           bool
	ChangedURL      bool
	ChangedBody     bool
	ChangedHeaders  bool
	ChangedTrailers bool
	ChangedStatus   bool
}

const (
	maxScriptHeaderFields     = 256
	maxScriptHeaderValues     = 512
	maxScriptHeaderValueBytes = 16 << 10
)

func newScriptRuntime(statePath ...string) *scriptRuntime {
	runtime := &scriptRuntime{
		programs:     make(map[string]*goja.Program),
		persistent:   make(map[string]map[string]string),
		networkSlots: make(chan struct{}, maxConcurrentModuleNetworkCalls),
	}
	if len(statePath) > 0 {
		runtime.statePath = statePath[0]
		if err := runtime.loadPersistent(); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("intercept: ignoring invalid native extension store: %v", err)
		}
	}
	return runtime
}

func (r *scriptRuntime) prune(modules []Module) {
	ids := make([]string, 0, len(modules))
	allowed := make(map[string]struct{}, len(modules))
	for _, module := range modules {
		if !module.PersistentStorage {
			continue
		}
		ids = append(ids, module.ID)
		allowed[module.ID] = struct{}{}
	}
	sort.Strings(ids)
	signature := strings.Join(ids, "\n")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.moduleSetReady && signature == r.moduleSet {
		return
	}
	changed := false
	for moduleID := range r.persistent {
		if _, exists := allowed[moduleID]; !exists {
			delete(r.persistent, moduleID)
			changed = true
		}
	}
	r.moduleSet = signature
	r.moduleSetReady = true
	if changed {
		if err := r.savePersistentLocked(); err != nil {
			log.Printf("intercept: native extension store prune failed: %v", err)
		}
	}
}

func (r *scriptRuntime) execute(ctx context.Context, cfg Config, roots *x509.CertPool, module Module, rule ScriptRule, request scriptMessage, response *scriptMessage) (scriptResult, error) {
	program, err := r.program(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	settings, err := moduleSettingValues(module)
	if err != nil {
		return scriptResult{}, err
	}
	vm := goja.New()
	installConsoleAPI(vm, module.ID, rule.ID)
	actionCtx, cancelAction := context.WithTimeout(ctx, time.Duration(rule.TimeoutMS)*time.Millisecond)
	defer cancelAction()
	requestObject, err := scriptMessageObject(vm, request, "none")
	if err != nil {
		return scriptResult{}, err
	}
	contextObject := map[string]any{
		"phase":    rule.Phase,
		"request":  requestObject,
		"settings": settings,
	}
	if response != nil {
		responseObject, objectErr := scriptMessageObject(vm, *response, rule.BodyMode)
		if objectErr != nil {
			return scriptResult{}, objectErr
		}
		contextObject["response"] = responseObject
	} else if rule.BodyMode != "none" {
		requestObject, err = scriptMessageObject(vm, request, rule.BodyMode)
		if err != nil {
			return scriptResult{}, err
		}
		contextObject["request"] = requestObject
	}
	if module.PersistentStorage {
		contextObject["storage"] = r.storageObject(vm, module.ID)
	}
	if len(module.NetworkOrigins) > 0 {
		contextObject["network"] = newModuleNetworkAPI(vm, actionCtx, cfg.UpstreamProxy, roots, module.NetworkOrigins, r.networkSlots)
	}

	stopInterrupt := context.AfterFunc(actionCtx, func() {
		vm.Interrupt("script execution canceled or timed out")
	})
	defer func() {
		stopInterrupt()
		vm.ClearInterrupt()
	}()
	_, runErr := vm.RunProgram(program)
	if runErr != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, runErr)
	}
	transform, ok := goja.AssertFunction(vm.Get("transform"))
	if !ok {
		return scriptResult{}, fmt.Errorf("extension %s action %s must define function transform(context)", module.ID, rule.ID)
	}
	value, callErr := transform(goja.Undefined(), vm.ToValue(contextObject))
	if callErr != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, callErr)
	}
	return parseNativeScriptResult(value, response != nil)
}

func (r *scriptRuntime) program(module Module, rule ScriptRule) (*goja.Program, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if program := r.programs[rule.ScriptDigest]; program != nil {
		return program, nil
	}
	filename := firstNonEmpty(rule.ScriptURL, "extension:"+module.ID+"/"+rule.ID)
	program, err := goja.Compile(filename, rule.ScriptBody, false)
	if err != nil {
		return nil, fmt.Errorf("compile action %s: %w", rule.ID, err)
	}
	r.programs[rule.ScriptDigest] = program
	return program, nil
}

func parseNativeScriptResult(value goja.Value, responsePhase bool) (scriptResult, error) {
	result := scriptResult{}
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return result, nil
	}
	object, ok := stringAnyMap(value.Export())
	if !ok {
		return result, errors.New("transform(context) must return an object, null, or undefined")
	}
	for key := range object {
		if key != "abort" && key != "request" && key != "response" {
			return result, fmt.Errorf("transform result contains unsupported field %q", key)
		}
	}
	if raw, exists := object["abort"]; exists {
		abort, ok := raw.(bool)
		if !ok {
			return result, errors.New("transform.abort must be a boolean")
		}
		result.Abort = abort
	}
	requestPatch, hasRequest := object["request"]
	responsePatch, hasResponse := object["response"]
	if responsePhase && hasRequest {
		return result, errors.New("a response action cannot return a request patch")
	}
	if !responsePhase && hasRequest && hasResponse {
		return result, errors.New("a request action cannot return request and synthetic response patches together")
	}
	if hasRequest {
		if err := applyNativePatch(&result, requestPatch, false); err != nil {
			return scriptResult{}, err
		}
	}
	if hasResponse {
		if err := applyNativePatch(&result, responsePatch, true); err != nil {
			return scriptResult{}, err
		}
		result.Synthetic = !responsePhase
	}
	return result, nil
}

func applyNativePatch(result *scriptResult, raw any, response bool) error {
	object, ok := stringAnyMap(raw)
	if !ok {
		return errors.New("transform request/response patch must be an object")
	}
	for key := range object {
		if key != "url" && key != "headers" && key != "trailers" && key != "body" && key != "status" {
			return fmt.Errorf("transform patch contains unsupported field %q", key)
		}
	}
	if rawURL, exists := object["url"]; exists {
		if response {
			return errors.New("response patches cannot change the request URL")
		}
		value, ok := rawURL.(string)
		if !ok {
			return errors.New("request.url must be a string")
		}
		result.URL = value
		result.ChangedURL = true
	}
	if rawHeaders, exists := object["headers"]; exists {
		headers, err := exportedHeaders(rawHeaders)
		if err != nil {
			return err
		}
		if err := validateNativePatchHeaders(headers, response); err != nil {
			return err
		}
		result.Headers = headers
		result.ChangedHeaders = true
	}
	if rawTrailers, exists := object["trailers"]; exists {
		if !response {
			return errors.New("request patches cannot set trailers")
		}
		trailers, err := exportedTrailers(rawTrailers)
		if err != nil {
			return err
		}
		result.Trailers = trailers
		result.ChangedTrailers = true
	}
	if rawBody, exists := object["body"]; exists {
		body, err := exportedBody(rawBody)
		if err != nil {
			return err
		}
		result.Body = body
		result.ChangedBody = true
	}
	if rawStatus, exists := object["status"]; exists {
		if !response {
			return errors.New("request patches cannot set status")
		}
		status, err := exportedStatus(rawStatus)
		if err != nil {
			return err
		}
		result.StatusCode = status
		result.ChangedStatus = true
	}
	return nil
}

func (r *scriptRuntime) storageObject(vm *goja.Runtime, moduleID string) *goja.Object {
	get := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		r.mu.Lock()
		value, exists := r.persistent[moduleID][key]
		r.mu.Unlock()
		if !exists {
			return goja.Null()
		}
		return vm.ToValue(value)
	}
	set := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		value := call.Argument(1).String()
		if len(key) == 0 || len(key) > 256 || len(value) > 64<<10 {
			return vm.ToValue(false)
		}
		r.mu.Lock()
		bucket := r.persistent[moduleID]
		if bucket == nil {
			bucket = make(map[string]string)
			r.persistent[moduleID] = bucket
		}
		if len(bucket) >= 256 {
			if _, exists := bucket[key]; !exists {
				r.mu.Unlock()
				return vm.ToValue(false)
			}
		}
		previous, existed := bucket[key]
		bucket[key] = value
		if err := r.savePersistentLocked(); err != nil {
			if existed {
				bucket[key] = previous
			} else {
				delete(bucket, key)
			}
			r.mu.Unlock()
			return vm.ToValue(false)
		}
		r.mu.Unlock()
		return vm.ToValue(true)
	}
	remove := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		r.mu.Lock()
		bucket := r.persistent[moduleID]
		previous, existed := bucket[key]
		delete(bucket, key)
		if err := r.savePersistentLocked(); err != nil {
			if existed {
				bucket[key] = previous
			}
			r.mu.Unlock()
			return vm.ToValue(false)
		}
		r.mu.Unlock()
		return vm.ToValue(existed)
	}
	clear := func(goja.FunctionCall) goja.Value {
		r.mu.Lock()
		previous := r.persistent[moduleID]
		delete(r.persistent, moduleID)
		if err := r.savePersistentLocked(); err != nil {
			r.persistent[moduleID] = previous
			r.mu.Unlock()
			return vm.ToValue(false)
		}
		r.mu.Unlock()
		return vm.ToValue(true)
	}
	storage := vm.NewObject()
	_ = storage.Set("get", get)
	_ = storage.Set("set", set)
	_ = storage.Set("delete", remove)
	_ = storage.Set("clear", clear)
	return storage
}

func (r *scriptRuntime) loadPersistent() error {
	if r.statePath == "" {
		return nil
	}
	body, err := os.ReadFile(r.statePath)
	if err != nil {
		return err
	}
	if len(body) > 4<<20 {
		return errors.New("native extension store exceeds 4194304 bytes")
	}
	var state map[string]map[string]string
	if err := json.Unmarshal(body, &state); err != nil {
		return err
	}
	for moduleID, values := range state {
		if !validModuleID(moduleID) || len(values) > 256 {
			return errors.New("native extension store exceeds key limits")
		}
		for key, value := range values {
			if len(key) == 0 || len(key) > 256 || len(value) > 64<<10 {
				return errors.New("native extension store contains an oversized entry")
			}
		}
	}
	r.persistent = state
	return nil
}

func (r *scriptRuntime) savePersistentLocked() error {
	if r.statePath == "" {
		return nil
	}
	body, err := json.Marshal(r.persistent)
	if err != nil {
		return err
	}
	if len(body) > 4<<20 {
		return errors.New("native extension store exceeds 4194304 bytes")
	}
	dir := filepath.Dir(r.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".store-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, r.statePath)
}

func installConsoleAPI(vm *goja.Runtime, moduleID, actionID string) {
	console := vm.NewObject()
	logger := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, argument := range call.Arguments {
			text := strings.ReplaceAll(strings.ReplaceAll(argument.String(), "\r", `\r`), "\n", `\n`)
			parts = append(parts, truncateScriptLog(text, 512))
		}
		line := truncateScriptLog(strings.Join(parts, " "), 2048)
		log.Printf("intercept: extension=%s action=%s script=%q", moduleID, actionID, line)
		return goja.Undefined()
	}
	_ = console.Set("log", logger)
	_ = console.Set("info", logger)
	_ = console.Set("warn", logger)
	_ = console.Set("error", logger)
	_ = vm.Set("console", console)
}

func truncateScriptLog(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	prefix := value[:limit]
	for !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + "..."
}

func scriptMessageObject(vm *goja.Runtime, message scriptMessage, bodyMode string) (map[string]any, error) {
	object := map[string]any{
		"url":     message.URL,
		"headers": flatHeaders(message.Headers),
	}
	switch bodyMode {
	case "none":
	case "text":
		object["body"] = string(message.Body)
	case "binary":
		constructor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
		if !ok {
			return nil, errors.New("Uint8Array constructor is unavailable")
		}
		value, err := constructor(nil, vm.ToValue(vm.NewArrayBuffer(append([]byte(nil), message.Body...))))
		if err != nil {
			return nil, err
		}
		object["body"] = value
	default:
		return nil, fmt.Errorf("unsupported body mode %q", bodyMode)
	}
	if message.Method != "" {
		object["method"] = message.Method
	}
	if message.StatusCode != 0 {
		object["status"] = message.StatusCode
		object["trailers"] = flatHeaders(message.Trailers)
	}
	return object, nil
}

func exportedBody(value any) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return []byte(typed), nil
	case []byte:
		return append([]byte(nil), typed...), nil
	case goja.ArrayBuffer:
		return append([]byte(nil), typed.Bytes()...), nil
	case []any:
		out := make([]byte, len(typed))
		for index, item := range typed {
			number, ok := item.(int64)
			if !ok || number < 0 || number > 255 {
				return nil, errors.New("body contains a non-byte value")
			}
			out[index] = byte(number)
		}
		return out, nil
	default:
		return nil, errors.New("body must be a string or Uint8Array")
	}
}

func flatHeaders(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func stringAnyMap(value any) (map[string]any, bool) {
	typed, ok := value.(map[string]any)
	return typed, ok
}

func exportedHeaders(value any) (http.Header, error) {
	if typed, ok := value.(http.Header); ok {
		return exportedStringSliceHeaders(map[string][]string(typed))
	}
	if typed, ok := value.(map[string][]string); ok {
		return exportedStringSliceHeaders(typed)
	}
	if typed, ok := value.(map[string]string); ok {
		names, err := validatedScriptHeaderNames(mapKeysString(typed))
		if err != nil {
			return nil, err
		}
		budget := scriptHeaderBudget{}
		headers := make(http.Header, len(names))
		for _, name := range names {
			if err := budget.addField(name); err != nil {
				return nil, err
			}
			item := typed[name]
			if err := budget.addValue(name, item); err != nil {
				return nil, err
			}
			headers[http.CanonicalHeaderKey(name)] = []string{item}
		}
		return headers, nil
	}
	object, ok := stringAnyMap(value)
	if !ok {
		return nil, errors.New("headers must be an object")
	}
	names, err := validatedScriptHeaderNames(mapKeysAny(object))
	if err != nil {
		return nil, err
	}
	budget := scriptHeaderBudget{}
	headers := make(http.Header, len(names))
	for _, name := range names {
		if err := budget.addField(name); err != nil {
			return nil, err
		}
		values, err := exportedHeaderValues(name, object[name], &budget)
		if err != nil {
			return nil, err
		}
		headers[http.CanonicalHeaderKey(name)] = values
	}
	return headers, nil
}

func exportedStringSliceHeaders(values map[string][]string) (http.Header, error) {
	names, err := validatedScriptHeaderNames(mapKeysStringSlice(values))
	if err != nil {
		return nil, err
	}
	budget := scriptHeaderBudget{}
	headers := make(http.Header, len(names))
	for _, name := range names {
		if err := budget.addField(name); err != nil {
			return nil, err
		}
		exported, err := exportedHeaderValues(name, values[name], &budget)
		if err != nil {
			return nil, err
		}
		headers[http.CanonicalHeaderKey(name)] = exported
	}
	return headers, nil
}

type scriptHeaderBudget struct {
	values int
	bytes  int64
}

func (b *scriptHeaderBudget) addField(name string) error {
	b.bytes += int64(len(name))
	if b.bytes > maxModuleNetworkHeaderBytes {
		return fmt.Errorf("script headers exceed %d bytes", maxModuleNetworkHeaderBytes)
	}
	return nil
}

func (b *scriptHeaderBudget) addValue(name, value string) error {
	if !validHTTPHeaderValue(value) {
		return fmt.Errorf("invalid header value for %s", name)
	}
	if len(value) > maxScriptHeaderValueBytes {
		return fmt.Errorf("header value for %s exceeds %d bytes", name, maxScriptHeaderValueBytes)
	}
	b.values++
	if b.values > maxScriptHeaderValues {
		return fmt.Errorf("script headers exceed %d values", maxScriptHeaderValues)
	}
	b.bytes += int64(len(value))
	if b.bytes > maxModuleNetworkHeaderBytes {
		return fmt.Errorf("script headers exceed %d bytes", maxModuleNetworkHeaderBytes)
	}
	return nil
}

func exportedHeaderValues(name string, raw any, budget *scriptHeaderBudget) ([]string, error) {
	switch typed := raw.(type) {
	case []string:
		if len(typed) > maxScriptHeaderValues-budget.values {
			return nil, fmt.Errorf("script headers exceed %d values", maxScriptHeaderValues)
		}
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if err := budget.addValue(name, item); err != nil {
				return nil, err
			}
			values = append(values, item)
		}
		return values, nil
	case []any:
		if len(typed) > maxScriptHeaderValues-budget.values {
			return nil, fmt.Errorf("script headers exceed %d values", maxScriptHeaderValues)
		}
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, err := exportedHeaderScalar(item)
			if err != nil {
				return nil, fmt.Errorf("invalid header value for %s: %w", name, err)
			}
			if err := budget.addValue(name, text); err != nil {
				return nil, err
			}
			values = append(values, text)
		}
		return values, nil
	}
	text, err := exportedHeaderScalar(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid header value for %s: %w", name, err)
	}
	if err := budget.addValue(name, text); err != nil {
		return nil, err
	}
	return []string{text}, nil
}

func exportedHeaderScalar(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return fmt.Sprint(typed), nil
	default:
		return "", errors.New("header values must be strings or scalar values")
	}
}

func validatedScriptHeaderNames(names []string) ([]string, error) {
	if len(names) > maxScriptHeaderFields {
		return nil, fmt.Errorf("script headers exceed %d fields", maxScriptHeaderFields)
	}
	sort.Strings(names)
	seen := make(map[string]string, len(names))
	for _, name := range names {
		if !validModuleNetworkHeaderName(name) {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		folded := strings.ToLower(name)
		if previous, exists := seen[folded]; exists {
			return nil, fmt.Errorf("duplicate header names %q and %q", previous, name)
		}
		seen[folded] = name
	}
	return names, nil
}

func mapKeysString(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	return names
}

func mapKeysAny(values map[string]any) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	return names
}

func mapKeysStringSlice(values map[string][]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	return names
}

func validHTTPHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		item := value[index]
		if item == 0x7f || item < ' ' && item != '\t' {
			return false
		}
	}
	return true
}

func exportedTrailers(value any) (http.Header, error) {
	trailers, err := exportedHeaders(value)
	if err != nil {
		return nil, err
	}
	for name := range trailers {
		if !validResponseTrailerName(name) {
			return nil, fmt.Errorf("invalid trailer %q", name)
		}
	}
	return trailers, nil
}

func exportedStatus(value any) (int, error) {
	var status int
	switch typed := value.(type) {
	case int64:
		status = int(typed)
	case int32:
		status = int(typed)
	case int:
		status = typed
	case float64:
		status = int(typed)
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		if err != nil {
			return 0, errors.New("status must be an integer")
		}
		status = parsed
	default:
		return 0, errors.New("status must be an integer")
	}
	if status < 100 || status > 599 {
		return 0, errors.New("status must be between 100 and 599")
	}
	return status, nil
}

type matchedScriptRule struct {
	Module Module
	Rule   ScriptRule
}

type compiledScriptRule struct {
	rule  ScriptRule
	path  *regexp.Regexp
	hosts *compiledHostMatcher
}

type compiledScriptModule struct {
	module Module
	rules  []compiledScriptRule
	hosts  *compiledHostMatcher
}

type compiledHostMatcher struct {
	exact    map[string]struct{}
	wildcard []string
}

func newCompiledHostMatcher(patterns []string) *compiledHostMatcher {
	matcher := &compiledHostMatcher{exact: make(map[string]struct{}, len(patterns))}
	seenWildcard := make(map[string]struct{})
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if _, exists := seenWildcard[suffix]; !exists {
				seenWildcard[suffix] = struct{}{}
				matcher.wildcard = append(matcher.wildcard, suffix)
			}
			continue
		}
		matcher.exact[pattern] = struct{}{}
	}
	return matcher
}

func (m *compiledHostMatcher) Match(value string) bool {
	if m == nil {
		return false
	}
	host := canonicalHost(value)
	if _, exists := m.exact[host]; exists {
		return true
	}
	for _, suffix := range m.wildcard {
		separator := len(host) - len(suffix) - 1
		if separator > 0 && host[separator] == '.' && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// compiledScriptConfig belongs to one validated Config snapshot. ConfigStore
// replaces the pointer on a successful reload, so regexp programs and ordered
// module lookup state are bounded by config lifetime rather than a global cache.
type compiledScriptConfig struct {
	modules        []compiledScriptModule
	moduleHosts    map[string]*compiledHostMatcher
	activeHosts    *compiledHostMatcher
	activePatterns []string
}

func compileScriptConfig(cfg Config) (*compiledScriptConfig, error) {
	byID := make(map[string]Module, len(cfg.Modules))
	for _, module := range cfg.Modules {
		byID[module.ID] = module
	}
	compiled := &compiledScriptConfig{
		modules:     make([]compiledScriptModule, 0, len(cfg.Modules)),
		moduleHosts: make(map[string]*compiledHostMatcher, len(cfg.Modules)),
	}
	activePatterns := make([]string, 0, 16)
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		compiled.moduleHosts[module.ID] = newCompiledHostMatcher(module.CaptureHosts)
		if cfg.MITM.Enabled {
			activePatterns = append(activePatterns, module.CaptureHosts...)
		}
	}
	compiled.activePatterns = uniqueSorted(activePatterns)
	compiled.activeHosts = newCompiledHostMatcher(compiled.activePatterns)
	for _, moduleID := range cfg.ExecutionOrder {
		module, exists := byID[moduleID]
		if !exists || !module.Enabled {
			continue
		}
		entry := compiledScriptModule{
			module: module,
			rules:  make([]compiledScriptRule, 0, len(module.Scripts)),
			hosts:  compiled.moduleHosts[module.ID],
		}
		for _, rule := range module.Scripts {
			path, err := regexp.Compile(rule.Match.PathRegex)
			if err != nil {
				return nil, fmt.Errorf("extension %s action %s path_regex: %w", module.ID, rule.ID, err)
			}
			entry.rules = append(entry.rules, compiledScriptRule{
				rule:  rule,
				path:  path,
				hosts: newCompiledHostMatcher(rule.Match.Hosts),
			})
		}
		compiled.modules = append(compiled.modules, entry)
	}
	return compiled, nil
}

func matchingScriptRules(cfg Config, phase string, message scriptMessage) []matchedScriptRule {
	parsed, err := url.Parse(message.URL)
	if err != nil {
		return nil
	}
	host := canonicalHost(parsed.Hostname())
	scheme := strings.ToLower(parsed.Scheme)
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	runtime := cfg.runtime
	if runtime == nil {
		runtime, err = compileScriptConfig(cfg)
		if err != nil {
			return nil
		}
	}
	var matched []matchedScriptRule
	for _, compiledModule := range runtime.modules {
		module := compiledModule.module
		if !compiledModule.hosts.Match(host) {
			continue
		}
		for _, compiledRule := range compiledModule.rules {
			rule := compiledRule.rule
			if rule.Phase != phase || !compiledRule.hosts.Match(host) || !containsString(rule.Match.Schemes, scheme) {
				continue
			}
			if len(rule.Match.Methods) > 0 && !containsString(rule.Match.Methods, message.Method) {
				continue
			}
			if len(rule.Match.StatusCodes) > 0 && !containsInt(rule.Match.StatusCodes, message.StatusCode) {
				continue
			}
			if compiledRule.path.MatchString(path) {
				matched = append(matched, matchedScriptRule{Module: module, Rule: rule})
			}
		}
	}
	return matched
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
