package main

import (
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
}

type scriptMessage struct {
	URL        string
	Method     string
	Headers    http.Header
	Body       []byte
	StatusCode int
}

type scriptResult struct {
	URL            string
	Headers        http.Header
	Body           []byte
	StatusCode     int
	Synthetic      bool
	Abort          bool
	ChangedURL     bool
	ChangedBody    bool
	ChangedHeaders bool
	ChangedStatus  bool
}

func newScriptRuntime(statePath ...string) *scriptRuntime {
	runtime := &scriptRuntime{
		programs:   make(map[string]*goja.Program),
		persistent: make(map[string]map[string]string),
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

func (r *scriptRuntime) execute(module Module, rule ScriptRule, request scriptMessage, response *scriptMessage) (scriptResult, error) {
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

	timer := time.AfterFunc(time.Duration(rule.TimeoutMS)*time.Millisecond, func() {
		vm.Interrupt("script execution timed out")
	})
	_, runErr := vm.RunProgram(program)
	if runErr != nil {
		timer.Stop()
		vm.ClearInterrupt()
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, runErr)
	}
	transform, ok := goja.AssertFunction(vm.Get("transform"))
	if !ok {
		timer.Stop()
		vm.ClearInterrupt()
		return scriptResult{}, fmt.Errorf("extension %s action %s must define function transform(context)", module.ID, rule.ID)
	}
	value, callErr := transform(goja.Undefined(), vm.ToValue(contextObject))
	timer.Stop()
	vm.ClearInterrupt()
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
		if key != "url" && key != "headers" && key != "body" && key != "status" {
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
		result.Headers = headers
		result.ChangedHeaders = true
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
	if typed, ok := value.(map[string]string); ok {
		headers := make(http.Header, len(typed))
		for name, item := range typed {
			if strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(item, "\r\n") {
				return nil, fmt.Errorf("invalid header %q", name)
			}
			headers.Set(name, item)
		}
		return headers, nil
	}
	object, ok := stringAnyMap(value)
	if !ok {
		return nil, errors.New("headers must be an object")
	}
	headers := make(http.Header, len(object))
	for name, raw := range object {
		if strings.ContainsAny(name, "\r\n:") || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		switch typed := raw.(type) {
		case string:
			if strings.ContainsAny(typed, "\r\n") {
				return nil, fmt.Errorf("invalid header value for %s", name)
			}
			headers.Set(name, typed)
		case []any:
			for _, item := range typed {
				text := fmt.Sprint(item)
				if strings.ContainsAny(text, "\r\n") {
					return nil, fmt.Errorf("invalid header value for %s", name)
				}
				headers.Add(name, text)
			}
		default:
			text := fmt.Sprint(raw)
			if strings.ContainsAny(text, "\r\n") {
				return nil, fmt.Errorf("invalid header value for %s", name)
			}
			headers.Set(name, text)
		}
	}
	return headers, nil
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

func matchingScriptRules(cfg Config, phase string, message scriptMessage) []struct {
	Module Module
	Rule   ScriptRule
} {
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
	var matched []struct {
		Module Module
		Rule   ScriptRule
	}
	for _, module := range cfg.Modules {
		if !module.Enabled || !moduleOwnsHost(module, host) {
			continue
		}
		for _, rule := range module.Scripts {
			if rule.Phase != phase || !matchRuleHost(rule.Match.Hosts, host) || !containsString(rule.Match.Schemes, scheme) {
				continue
			}
			if len(rule.Match.Methods) > 0 && !containsString(rule.Match.Methods, message.Method) {
				continue
			}
			if len(rule.Match.StatusCodes) > 0 && !containsInt(rule.Match.StatusCodes, message.StatusCode) {
				continue
			}
			pattern, compileErr := regexp.Compile(rule.Match.PathRegex)
			if compileErr == nil && pattern.MatchString(path) {
				matched = append(matched, struct {
					Module Module
					Rule   ScriptRule
				}{Module: module, Rule: rule})
			}
		}
	}
	return matched
}

func matchRuleHost(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
