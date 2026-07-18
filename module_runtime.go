package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	// goja uses regexp2 only when a JavaScript expression cannot be represented
	// by Go's linear-time RE2 engine. Bound that fallback independently of the
	// VM interrupt so catastrophic backtracking cannot pin a runtime goroutine.
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

func (r *scriptRuntime) prune(modules []Module) {
	ids := make([]string, 0, len(modules))
	allowed := make(map[string]struct{}, len(modules))
	for _, module := range modules {
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
			log.Printf("intercept: persistent module store prune failed: %v", err)
		}
	}
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
			log.Printf("intercept: persistent module store ignored: %v", err)
		}
	}
	return runtime
}

func (r *scriptRuntime) execute(module Module, rule ScriptRule, request scriptMessage, response *scriptMessage) (scriptResult, error) {
	program, err := r.program(rule)
	if err != nil {
		return scriptResult{}, err
	}
	vm := goja.New()
	result := scriptResult{}
	doneCalled := false
	doneHadArgument := false
	var doneValue goja.Value
	if err := vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		doneCalled = true
		doneHadArgument = len(call.Arguments) > 0
		doneValue = call.Argument(0)
		return goja.Undefined()
	}); err != nil {
		return scriptResult{}, err
	}
	requestObject, err := scriptMessageObject(vm, request, rule.BinaryBody)
	if err != nil {
		return scriptResult{}, err
	}
	if err := vm.Set("$request", requestObject); err != nil {
		return scriptResult{}, err
	}
	if response != nil {
		responseObject, objectErr := scriptMessageObject(vm, *response, rule.BinaryBody)
		if objectErr != nil {
			return scriptResult{}, objectErr
		}
		if err := vm.Set("$response", responseObject); err != nil {
			return scriptResult{}, err
		}
	}
	argument := rule.Argument
	if module.Argument != "" {
		argument = module.Argument
	}
	_ = vm.Set("$argument", argument)
	_ = vm.Set("$loon", "5gpn")
	r.installPersistentAPI(vm, module)
	installConsoleAPI(vm, module.ID, rule.ID)
	installDeniedNetworkAPI(vm)

	timer := time.AfterFunc(time.Duration(rule.TimeoutMS)*time.Millisecond, func() {
		vm.Interrupt("script execution timed out")
	})
	_, runErr := vm.RunProgram(program)
	timer.Stop()
	vm.ClearInterrupt()
	if runErr != nil {
		return scriptResult{}, fmt.Errorf("module %s rule %s: %w", module.ID, rule.ID, runErr)
	}
	if doneCalled && !doneHadArgument {
		result.Abort = true
		return result, nil
	}
	if !doneCalled || doneValue == nil || goja.IsUndefined(doneValue) || goja.IsNull(doneValue) {
		return result, nil
	}
	exported := doneValue.Export()
	if text, ok := exported.(string); ok {
		result.Body = []byte(text)
		result.ChangedBody = true
		return result, nil
	}
	object, ok := stringAnyMap(exported)
	if !ok {
		return scriptResult{}, errors.New("$done value must be an object, string, null, or undefined")
	}
	if nested, exists := object["response"]; exists {
		var nestedOK bool
		object, nestedOK = stringAnyMap(nested)
		if !nestedOK {
			return scriptResult{}, errors.New("$done.response must be an object")
		}
		result.Synthetic = true
	}
	if raw, exists := object["url"]; exists {
		value, ok := raw.(string)
		if !ok {
			return scriptResult{}, errors.New("$done.url must be a string")
		}
		result.URL = value
		result.ChangedURL = true
	}
	if raw, exists := object["body"]; exists {
		value, err := exportedBody(raw)
		if err != nil {
			return scriptResult{}, err
		}
		result.Body = value
		result.ChangedBody = true
	}
	if raw, exists := object["headers"]; exists {
		headers, err := exportedHeaders(raw)
		if err != nil {
			return scriptResult{}, err
		}
		result.Headers = headers
		result.ChangedHeaders = true
	}
	for _, key := range []string{"status", "statusCode"} {
		if raw, exists := object[key]; exists {
			status, err := exportedStatus(raw)
			if err != nil {
				return scriptResult{}, err
			}
			result.StatusCode = status
			result.ChangedStatus = true
			break
		}
	}
	if response == nil && result.ChangedStatus {
		result.Synthetic = true
	}
	return result, nil
}

func (r *scriptRuntime) program(rule ScriptRule) (*goja.Program, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if program := r.programs[rule.ScriptDigest]; program != nil {
		return program, nil
	}
	program, err := goja.Compile(rule.ScriptURL, rule.ScriptBody, false)
	if err != nil {
		return nil, fmt.Errorf("compile script %s: %w", rule.ID, err)
	}
	r.programs[rule.ScriptDigest] = program
	return program, nil
}

func (r *scriptRuntime) installPersistentAPI(vm *goja.Runtime, module Module) {
	parameterDefaults := make(map[string]string, len(module.Parameters))
	for _, parameter := range module.Parameters {
		parameterDefaults[parameter.Key] = parameter.Value
	}
	read := func(call goja.FunctionCall) goja.Value {
		key := call.Argument(0).String()
		if value, exists := parameterDefaults[key]; exists {
			return vm.ToValue(value)
		}
		r.mu.Lock()
		value, exists := r.persistent[module.ID][key]
		r.mu.Unlock()
		if !exists {
			return goja.Null()
		}
		return vm.ToValue(value)
	}
	write := func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		key := call.Argument(1).String()
		if _, configured := parameterDefaults[key]; configured {
			return vm.ToValue(false)
		}
		if len(key) == 0 || len(key) > 256 || len(value) > 64<<10 {
			return vm.ToValue(false)
		}
		r.mu.Lock()
		bucket := r.persistent[module.ID]
		if bucket == nil {
			bucket = make(map[string]string)
			r.persistent[module.ID] = bucket
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
		bucket := r.persistent[module.ID]
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
	removeAll := func(goja.FunctionCall) goja.Value {
		r.mu.Lock()
		previous := r.persistent[module.ID]
		delete(r.persistent, module.ID)
		if err := r.savePersistentLocked(); err != nil {
			r.persistent[module.ID] = previous
			r.mu.Unlock()
			return vm.ToValue(false)
		}
		r.mu.Unlock()
		return vm.ToValue(true)
	}
	store := vm.NewObject()
	_ = store.Set("read", read)
	_ = store.Set("write", write)
	_ = store.Set("remove", remove)
	_ = store.Set("removeAll", removeAll)
	_ = vm.Set("$persistentStore", store)
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
		return errors.New("persistent module store exceeds 4194304 bytes")
	}
	var state map[string]map[string]string
	if err := json.Unmarshal(body, &state); err != nil {
		return err
	}
	for moduleID, values := range state {
		if !validModuleID(moduleID) || len(values) > 256 {
			return errors.New("persistent module store exceeds key limits")
		}
		for key, value := range values {
			if len(key) == 0 || len(key) > 256 || len(value) > 64<<10 {
				return errors.New("persistent module store contains an oversized entry")
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
		return errors.New("persistent module store exceeds 4194304 bytes")
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

func installConsoleAPI(vm *goja.Runtime, moduleID, ruleID string) {
	console := vm.NewObject()
	logger := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, argument := range call.Arguments {
			text := strings.ReplaceAll(strings.ReplaceAll(argument.String(), "\r", `\r`), "\n", `\n`)
			text = truncateScriptLog(text, 512)
			parts = append(parts, text)
		}
		line := strings.Join(parts, " ")
		line = truncateScriptLog(line, 2048)
		log.Printf("intercept: module=%s rule=%s script=%q", moduleID, ruleID, line)
		return goja.Undefined()
	}
	_ = console.Set("log", logger)
	_ = console.Set("info", logger)
	_ = console.Set("warn", logger)
	_ = console.Set("error", logger)
	_ = vm.Set("console", console)
	notify := func(call goja.FunctionCall) goja.Value {
		return logger(call)
	}
	notification := vm.NewObject()
	_ = notification.Set("post", notify)
	_ = vm.Set("$notification", notification)
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

func installDeniedNetworkAPI(vm *goja.Runtime) {
	denied := func(goja.FunctionCall) goja.Value {
		panic(vm.NewTypeError("module network access is disabled"))
	}
	client := vm.NewObject()
	for _, method := range []string{"get", "post", "put", "delete", "head", "patch"} {
		_ = client.Set(method, denied)
	}
	_ = vm.Set("$httpClient", client)
}

func scriptMessageObject(vm *goja.Runtime, message scriptMessage, binary bool) (map[string]any, error) {
	object := map[string]any{
		"url":     message.URL,
		"headers": flatHeaders(message.Headers),
	}
	if binary {
		constructor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
		if !ok {
			return nil, errors.New("Uint8Array constructor is unavailable")
		}
		value, err := constructor(nil, vm.ToValue(vm.NewArrayBuffer(append([]byte(nil), message.Body...))))
		if err != nil {
			return nil, err
		}
		object["body"] = value
	} else {
		object["body"] = string(message.Body)
	}
	if message.Method != "" {
		object["method"] = message.Method
	}
	if message.StatusCode != 0 {
		object["status"] = message.StatusCode
		object["statusCode"] = message.StatusCode
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
				return nil, errors.New("$done.body contains a non-byte value")
			}
			out[index] = byte(number)
		}
		return out, nil
	default:
		return nil, errors.New("$done.body must be a string or Uint8Array")
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
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	default:
		return nil, false
	}
}

func exportedHeaders(value any) (http.Header, error) {
	switch typed := value.(type) {
	case map[string]string:
		headers := make(http.Header, len(typed))
		for name, item := range typed {
			if strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(item, "\r\n") {
				return nil, fmt.Errorf("invalid response header %q", name)
			}
			headers.Set(name, item)
		}
		return headers, nil
	case http.Header:
		return cloneProxyHeaders(typed), nil
	}
	object, ok := stringAnyMap(value)
	if !ok {
		return nil, errors.New("$done.headers must be an object")
	}
	headers := make(http.Header, len(object))
	for name, raw := range object {
		if strings.ContainsAny(name, "\r\n:") || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid response header name %q", name)
		}
		switch typed := raw.(type) {
		case string:
			if strings.ContainsAny(typed, "\r\n") {
				return nil, fmt.Errorf("invalid response header value for %s", name)
			}
			headers.Set(name, typed)
		case []any:
			for _, item := range typed {
				text := fmt.Sprint(item)
				if strings.ContainsAny(text, "\r\n") {
					return nil, fmt.Errorf("invalid response header value for %s", name)
				}
				headers.Add(name, text)
			}
		default:
			text := fmt.Sprint(raw)
			if strings.ContainsAny(text, "\r\n") {
				return nil, fmt.Errorf("invalid response header value for %s", name)
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
	case string:
		fields := strings.Fields(typed)
		for _, field := range fields {
			parsed, err := strconv.Atoi(field)
			if err == nil && parsed >= 100 && parsed <= 599 {
				status = parsed
				break
			}
		}
		if status == 0 {
			return 0, errors.New("$done status is invalid")
		}
	default:
		return 0, errors.New("$done status is invalid")
	}
	if status < 100 || status > 599 {
		return 0, errors.New("$done status must be between 100 and 599")
	}
	return status, nil
}

func matchingScriptRules(cfg Config, phase, requestURL string) []struct {
	Module Module
	Rule   ScriptRule
} {
	var matched []struct {
		Module Module
		Rule   ScriptRule
	}
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		for _, rule := range module.Scripts {
			if rule.Phase != phase {
				continue
			}
			pattern, err := regexp.Compile(rule.Pattern)
			if err == nil && pattern.MatchString(requestURL) {
				matched = append(matched, struct {
					Module Module
					Rule   ScriptRule
				}{Module: module, Rule: rule})
			}
		}
	}
	return matched
}

func matchingRewriteRules(cfg Config, requestURL string) []struct {
	Module Module
	Rule   RewriteRule
	RE     *regexp.Regexp
} {
	var matched []struct {
		Module Module
		Rule   RewriteRule
		RE     *regexp.Regexp
	}
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		for _, rule := range module.Rewrites {
			pattern, err := regexp.Compile(rule.Pattern)
			if err == nil && pattern.MatchString(requestURL) {
				matched = append(matched, struct {
					Module Module
					Rule   RewriteRule
					RE     *regexp.Regexp
				}{Module: module, Rule: rule, RE: pattern})
			}
		}
	}
	return matched
}

func matchingHeaderRules(cfg Config, requestURL string) []struct {
	Module Module
	Rule   HeaderRule
} {
	var matched []struct {
		Module Module
		Rule   HeaderRule
	}
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		for _, rule := range module.Headers {
			pattern, err := regexp.Compile(rule.Pattern)
			if err == nil && pattern.MatchString(requestURL) {
				matched = append(matched, struct {
					Module Module
					Rule   HeaderRule
				}{Module: module, Rule: rule})
			}
		}
	}
	return matched
}
