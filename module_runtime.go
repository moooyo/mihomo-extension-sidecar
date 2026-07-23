package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2/v2"
	"github.com/dop251/goja"
)

func init() {
	regexp2.DefaultMatchTimeout = 250 * time.Millisecond
}

type scriptRuntime struct {
	persistent        atomic.Pointer[persistentSnapshot]
	persistentWriteMu sync.Mutex
	persistentLoadErr error
	persistPersistent func(*persistentSnapshot) error
	statePath         string
	networkSlots      chan struct{}
	logs              engineLogPublisher
}

// persistentSnapshot and every map reachable from it are immutable after
// publication. Mutations copy the outer map and only the affected module
// bucket before synchronously committing and publishing a replacement.
type persistentSnapshot struct {
	modules map[string]map[string]string
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
	maxConsoleLogsPerAction   = 128
	maxConsoleLogArguments    = 16
	maxConsoleArgumentBytes   = 512
	maxPersistentStoreBytes   = 4 << 20
	maxPersistentKeys         = 256
	maxPersistentKeyBytes     = 256
	maxPersistentValueBytes   = 64 << 10
)

func newScriptRuntime(statePath ...string) *scriptRuntime {
	return newScriptRuntimeWithLogs(nil, statePath...)
}

func newScriptRuntimeWithLogs(logs engineLogPublisher, statePath ...string) *scriptRuntime {
	runtime := &scriptRuntime{
		networkSlots: make(chan struct{}, maxConcurrentModuleNetworkCalls),
		logs:         logs,
	}
	runtime.persistent.Store(newPersistentSnapshot())
	runtime.persistPersistent = runtime.savePersistent
	if len(statePath) > 0 {
		runtime.statePath = statePath[0]
		loaded, err := runtime.loadPersistent()
		switch {
		case err == nil:
			runtime.persistent.Store(loaded)
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			runtime.persistentLoadErr = err
			log.Printf("intercept: native extension store unavailable; mutations disabled until restart: %v", err)
		}
	}
	return runtime
}

func (r *scriptRuntime) execute(ctx context.Context, cfg Config, roots *x509.CertPool, module Module, rule ScriptRule, request scriptMessage, response *scriptMessage) (result scriptResult, err error) {
	started := time.Now()
	actionCtx, cancelAction := context.WithTimeout(ctx, time.Duration(rule.TimeoutMS)*time.Millisecond)
	defer cancelAction()
	defer func() {
		if !engineLogPublishingEnabled(r.logs) {
			return
		}
		event := EngineLog{
			Level: "info", Source: "engine", Extension: module.ID, Action: rule.ID,
			Phase: rule.Phase, DurationMS: float64(time.Since(started).Nanoseconds()) / 1e6,
			URL: sanitizeEngineLogURL(request.URL), ScriptDigest: rule.ScriptDigest, Message: "action completed",
		}
		if err != nil {
			event.Level = "error"
			switch {
			case errors.Is(actionCtx.Err(), context.DeadlineExceeded):
				event.Level = "warn"
				event.Message = "action timed out"
			case errors.Is(ctx.Err(), context.Canceled):
				event.Level = "warn"
				event.Message = "action canceled"
			default:
				event.Message = "action failed: " + err.Error()
			}
		}
		r.logs.Publish(event)
	}()
	program, err := scriptProgram(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	settings, err := scriptSettingValues(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	vm := goja.New()
	installConsoleAPI(vm, r.logs, EngineLog{
		Source: "script", Extension: module.ID, Action: rule.ID, Phase: rule.Phase,
		URL: request.URL, ScriptDigest: rule.ScriptDigest,
	})
	requestBodyMode := "none"
	if response == nil {
		requestBodyMode = rule.BodyMode
	}
	requestObject, err := scriptMessageObject(vm, request, requestBodyMode)
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
	}
	if module.PersistentStorage {
		contextObject["storage"] = r.storageObject(vm, module.ID)
	}
	if len(module.NetworkOrigins) > 0 {
		network, closeNetwork := newModuleNetworkAPI(vm, actionCtx, cfg.UpstreamProxy, roots, module.NetworkOrigins, r.networkSlots)
		defer closeNetwork()
		contextObject["network"] = network
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

func scriptProgram(module Module, rule ScriptRule) (*goja.Program, error) {
	if rule.program != nil {
		return rule.program, nil
	}
	filename := firstNonEmpty(rule.ScriptURL, "extension:"+module.ID+"/"+rule.ID)
	program, err := goja.Compile(filename, rule.ScriptBody, false)
	if err != nil {
		return nil, fmt.Errorf("compile action %s: %w", rule.ID, err)
	}
	return program, nil
}

func scriptSettingValues(module Module, rule ScriptRule) (map[string]any, error) {
	if rule.settings != nil {
		return cloneScriptSettings(rule.settings), nil
	}
	return moduleSettingValues(module)
}

func cloneScriptSettings(settings map[string]any) map[string]any {
	clone := make(map[string]any, len(settings))
	for key, value := range settings {
		clone[key] = cloneScriptSettingValue(value)
	}
	return clone
}

func cloneScriptSettingValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneScriptSettings(typed)
	case []any:
		clone := make([]any, len(typed))
		for index, item := range typed {
			clone[index] = cloneScriptSettingValue(item)
		}
		return clone
	default:
		return typed
	}
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
		snapshot := r.persistent.Load()
		if snapshot == nil {
			return goja.Null()
		}
		value, exists := snapshot.modules[moduleID][key]
		if !exists {
			return goja.Null()
		}
		return vm.ToValue(value)
	}
	set := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		value := call.Argument(1).String()
		if len(key) == 0 || len(key) > maxPersistentKeyBytes || len(value) > maxPersistentValueBytes {
			return vm.ToValue(false)
		}
		r.persistentWriteMu.Lock()
		defer r.persistentWriteMu.Unlock()
		if r.persistentLoadErr != nil {
			return vm.ToValue(false)
		}
		current := r.persistent.Load()
		bucket := current.modules[moduleID]
		if len(bucket) >= maxPersistentKeys {
			if _, exists := bucket[key]; !exists {
				return vm.ToValue(false)
			}
		}
		previous, existed := bucket[key]
		if existed && previous == value {
			return vm.ToValue(true)
		}
		nextModules := clonePersistentModules(current.modules)
		nextBucket := clonePersistentBucket(bucket)
		nextBucket[key] = value
		nextModules[moduleID] = nextBucket
		next := &persistentSnapshot{modules: nextModules}
		if err := r.persistPersistent(next); err != nil {
			return vm.ToValue(false)
		}
		r.persistent.Store(next)
		return vm.ToValue(true)
	}
	remove := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		r.persistentWriteMu.Lock()
		defer r.persistentWriteMu.Unlock()
		if r.persistentLoadErr != nil {
			return vm.ToValue(false)
		}
		current := r.persistent.Load()
		bucket := current.modules[moduleID]
		_, existed := bucket[key]
		if !existed {
			return vm.ToValue(false)
		}
		nextModules := clonePersistentModules(current.modules)
		nextBucket := clonePersistentBucket(bucket)
		delete(nextBucket, key)
		nextModules[moduleID] = nextBucket
		next := &persistentSnapshot{modules: nextModules}
		if err := r.persistPersistent(next); err != nil {
			return vm.ToValue(false)
		}
		r.persistent.Store(next)
		return vm.ToValue(true)
	}
	clear := func(goja.FunctionCall) goja.Value {
		r.persistentWriteMu.Lock()
		defer r.persistentWriteMu.Unlock()
		if r.persistentLoadErr != nil {
			return vm.ToValue(false)
		}
		current := r.persistent.Load()
		_, exists := current.modules[moduleID]
		if !exists {
			return vm.ToValue(true)
		}
		nextModules := clonePersistentModules(current.modules)
		delete(nextModules, moduleID)
		next := &persistentSnapshot{modules: nextModules}
		if err := r.persistPersistent(next); err != nil {
			return vm.ToValue(false)
		}
		r.persistent.Store(next)
		return vm.ToValue(true)
	}
	storage := vm.NewObject()
	_ = storage.Set("get", get)
	_ = storage.Set("set", set)
	_ = storage.Set("delete", remove)
	_ = storage.Set("clear", clear)
	return storage
}

func newPersistentSnapshot() *persistentSnapshot {
	return &persistentSnapshot{modules: make(map[string]map[string]string)}
}

func clonePersistentModules(modules map[string]map[string]string) map[string]map[string]string {
	clone := make(map[string]map[string]string, len(modules))
	for moduleID, bucket := range modules {
		clone[moduleID] = bucket
	}
	return clone
}

func clonePersistentBucket(bucket map[string]string) map[string]string {
	clone := make(map[string]string, len(bucket)+1)
	for key, value := range bucket {
		clone[key] = value
	}
	return clone
}

func (r *scriptRuntime) loadPersistent() (*persistentSnapshot, error) {
	if r.statePath == "" {
		return newPersistentSnapshot(), nil
	}
	file, err := os.Open(r.statePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxPersistentStoreBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPersistentStoreBytes {
		return nil, errors.New("native extension store exceeds 4194304 bytes")
	}
	if !utf8.Valid(body) {
		return nil, errors.New("native extension store is not valid UTF-8")
	}
	var state map[string]map[string]string
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("native extension store must be a JSON object")
	}
	for moduleID, values := range state {
		if !validModuleID(moduleID) || values == nil || len(values) > maxPersistentKeys {
			return nil, errors.New("native extension store exceeds key limits")
		}
		for key, value := range values {
			if len(key) == 0 || len(key) > maxPersistentKeyBytes || len(value) > maxPersistentValueBytes {
				return nil, errors.New("native extension store contains an oversized entry")
			}
		}
	}
	return &persistentSnapshot{modules: state}, nil
}

func marshalPersistentSnapshot(snapshot *persistentSnapshot) ([]byte, error) {
	if snapshot == nil || snapshot.modules == nil {
		return nil, errors.New("native extension store snapshot is uninitialized")
	}
	body, err := json.Marshal(snapshot.modules)
	if err != nil {
		return nil, err
	}
	if len(body) > maxPersistentStoreBytes {
		return nil, errors.New("native extension store exceeds 4194304 bytes")
	}
	return body, nil
}

func (r *scriptRuntime) savePersistent(snapshot *persistentSnapshot) error {
	if r.statePath == "" {
		return nil
	}
	body, err := marshalPersistentSnapshot(snapshot)
	if err != nil {
		return err
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

func installConsoleAPI(vm *goja.Runtime, publisher engineLogPublisher, metadata EngineLog) {
	console := vm.NewObject()
	published := 0
	limitReported := false
	metadataNormalized := false
	logger := func(level string) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			if !engineLogPublishingEnabled(publisher) {
				return goja.Undefined()
			}
			if !metadataNormalized {
				metadata.URL = sanitizeEngineLogURL(metadata.URL)
				metadataNormalized = true
			}
			if published >= maxConsoleLogsPerAction {
				if !limitReported {
					limitReported = true
					warning := metadata
					warning.Source = "engine"
					warning.Level = "warn"
					warning.Message = "console output limit reached; further messages suppressed"
					publisher.Publish(warning)
				}
				return goja.Undefined()
			}
			var message strings.Builder
			for index, argument := range call.Arguments {
				if index >= maxConsoleLogArguments || message.Len() >= maxEngineLogMessageBytes {
					break
				}
				if index > 0 {
					message.WriteByte(' ')
				}
				remaining := maxEngineLogMessageBytes - message.Len()
				if remaining > maxConsoleArgumentBytes {
					remaining = maxConsoleArgumentBytes
				}
				message.WriteString(boundedConsoleArgument(argument, remaining))
			}
			event := metadata
			event.Level = level
			event.Message = truncateEngineLogField(message.String(), maxEngineLogMessageBytes)
			publisher.Publish(event)
			published++
			return goja.Undefined()
		}
	}
	_ = console.Set("log", logger("info"))
	_ = console.Set("info", logger("info"))
	_ = console.Set("warn", logger("warn"))
	_ = console.Set("error", logger("error"))
	_ = vm.Set("console", console)
}

func boundedConsoleArgument(argument goja.Value, limit int) string {
	if limit <= 0 {
		return ""
	}
	value := argument.ToString()
	text, ok := value.(goja.String)
	if !ok {
		return truncateEngineLogField(value.String(), limit)
	}
	units := text.Length()
	if units > limit {
		units = limit
	}
	raw := text.Substring(0, units).String()
	raw = strings.ReplaceAll(strings.ReplaceAll(raw, "\r", `\r`), "\n", `\n`)
	return truncateEngineLogField(raw, limit)
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
// replaces the pointer on a successful reload, so JavaScript and regexp
// programs, decoded settings, and ordered module lookup state are bounded by
// config lifetime rather than a global cache.
type compiledScriptConfig struct {
	modules        []compiledScriptModule
	moduleHosts    map[string]*compiledHostMatcher
	activeHosts    *compiledHostMatcher
	activePatterns []string
}

func compileScriptConfig(cfg Config) (*compiledScriptConfig, error) {
	return compileScriptConfigWithPrograms(cfg, nil)
}

func compileScriptConfigWithPrograms(cfg Config, programs map[scriptProgramKey]*goja.Program) (*compiledScriptConfig, error) {
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
		settings, err := moduleSettingValues(module)
		if err != nil {
			return nil, fmt.Errorf("extension %s settings: %w", module.ID, err)
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
			program := programs[scriptProgramKey{moduleID: module.ID, actionID: rule.ID, digest: rule.ScriptDigest}]
			if program == nil {
				program, err = scriptProgram(module, rule)
				if err != nil {
					return nil, err
				}
			}
			rule.program = program
			rule.settings = settings
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
