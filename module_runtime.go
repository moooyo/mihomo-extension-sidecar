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
	// maxPersistentModuleBytes is the per-extension quota the architecture
	// document describes. Without it the only real bound was the global one:
	// 256 keys of 64 KiB is 16 MiB, four times the whole store, so one
	// extension could fill the budget and every other extension's
	// storage.set then returned false forever -- a cross-extension denial of
	// service with no log line anywhere.
	maxPersistentModuleBytes = 1 << 20
	maxPersistentKeys        = 256
	maxPersistentKeyBytes    = 256
	maxPersistentValueBytes  = 64 << 10
	// maxPersistentCommitsPerAction bounds durable store commits the way
	// maxConsoleLogsPerAction and maxModuleNetworkCallsPerAction bound the other
	// two script-reachable side channels. Storage had size bounds but no call
	// bound, and every accepted write marshals the whole store, writes it, fsyncs
	// it and renames it while holding the process-wide persistentWriteMu -- so one
	// extension looping storage.set with alternating values inside its rule
	// timeout was thousands of fsyncs, blocking every other extension's writes for
	// the duration. Only commits that actually reach the disk are counted: a set
	// that rewrites an identical value, a delete of a missing key and a clear of
	// an empty bucket all short-circuit before any I/O and cost nothing.
	maxPersistentCommitsPerAction = 32
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
	// Six declarative kinds, none of which reaches the JavaScript runtime: no
	// VM, no event loop, no proxy-client globals. Dispatch happens before the
	// script is compiled, because a declarative action carries none.
	switch {
	case rule.Reject:
		return scriptResult{Abort: true}, nil
	case rule.Mock != nil:
		return executeMock(rule, response != nil)
	case rule.Headers != nil:
		return executeHeaderEdits(rule, request, response)
	case rule.Rewrite != nil:
		return executeRewrite(rule, module, request)
	case rule.ReplaceBody != nil:
		return executeBodyReplace(rule, module, request, response)
	case rule.JQProgram != "":
		return r.executeJQ(actionCtx, module, rule, request, response)
	}
	program, err := scriptProgram(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	settings, err := scriptSettingValues(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	if err := loop.installTimerAPI(vm); err != nil {
		return scriptResult{}, err
	}
	if rule.Entry == scriptEntryProxyCompat {
		// Published bundles assume a browser-ish global set. Native scripts keep
		// the smaller surface they were reviewed against.
		if err := installWebAPI(vm); err != nil {
			return scriptResult{}, err
		}
		if err := installDOMAPI(vm); err != nil {
			return scriptResult{}, err
		}
	}
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
	var requester *moduleNetworkRequester
	if module.Network {
		// One requester, and one surface chosen from rule.Entry.
		//
		// Both used to be built on every granted action: newModuleNetworkAPI
		// makes its own requester, and a second bare one was made beside it.
		// Only ever one of them was reachable. Under the native entry the bare
		// requester has no consumer at all -- executeProxyCompat is the only
		// one, and it is not called; under proxy-compat, contextObject is never
		// handed to the VM (installProxyCompatAPI sets $-prefixed globals
		// instead), so contextObject["network"] was unreachable JavaScript.
		// Two requesters means two transport maps and two deferred Closes, and
		// a reader with no way to tell which one is live.
		requester = newModuleNetworkRequester(actionCtx, cfg.UpstreamProxy, roots, r.networkSlots)
		defer requester.Close()
		if rule.Entry != scriptEntryProxyCompat {
			contextObject["network"] = requester.newAPI(vm, loop)
		}
	}

	stopInterrupt := context.AfterFunc(actionCtx, func() {
		vm.Interrupt("script execution canceled or timed out")
	})
	defer func() {
		stopInterrupt()
		vm.ClearInterrupt()
	}()

	if rule.Entry == scriptEntryProxyCompat {
		return r.executeProxyCompat(actionCtx, vm, loop, program, module, rule, settings, requestObject, contextObject, requester, response != nil)
	}

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
	settled, settleErr := settlePromise(actionCtx, vm, loop, value)
	if settleErr != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, settleErr)
	}
	return parseNativeScriptResult(settled, response != nil)
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

// scriptSettingValues returns settings a caller may hand to a VM, which means
// the caller may see them mutated: context.settings and $argument are reachable
// from script code. rule.settings is the snapshot-owned map compileScriptConfig
// decoded once per module, so those callers get a copy.
func scriptSettingValues(module Module, rule ScriptRule) (map[string]any, error) {
	if rule.settings != nil {
		return cloneScriptSettings(rule.settings), nil
	}
	return moduleSettingValues(module)
}

// scriptSettingValuesReadOnly is for callers that only look values up.
//
// executeRewrite and executeBodyReplace pass the map straight to
// expandSettingsTemplate, which does nothing but read settings[key]. They are
// also the two cheapest action kinds -- the ones that exist precisely so a
// substitution does not have to construct a VM -- so a per-request deep copy of
// up to 128 decoded settings could cost more than the action itself.
//
// The returned map must not be mutated or handed to a VM. Use
// scriptSettingValues for that.
func scriptSettingValuesReadOnly(module Module, rule ScriptRule) (map[string]any, error) {
	if rule.settings != nil {
		return rule.settings, nil
	}
	return moduleSettingValues(module)
}

// actionGateOpen reports whether an action's enabled_when permits it to run.
//
// The setting's value is rendered to text and compared to the declared one, so
// a select gate matches the option string an operator picked and a boolean gate
// matches "true" or "false".
//
// An action with no gate, or one whose setting is absent from the values map,
// stays compiled: a document that reached this point has already been
// validated, and between wrongly dropping an action and wrongly keeping one,
// dropping is the failure an operator cannot see.
func actionGateOpen(rule ScriptRule, settings map[string]any) bool {
	if rule.EnabledWhen == nil {
		return true
	}
	value, ok := settings[rule.EnabledWhen.Key]
	if !ok {
		return true
	}
	return compatArgumentText(value) == rule.EnabledWhen.Equals
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
	// Per-action, because storageObject is built once per execute (the context
	// construction at the top of this file). goja runs one VM on one goroutine,
	// so a plain counter is enough -- the same shape module_network.go uses for
	// its call budget.
	commits := 0
	spend := func() bool {
		commits++
		return commits <= maxPersistentCommitsPerAction
	}
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
		if !spend() {
			return vm.ToValue(false)
		}
		nextModules := clonePersistentModules(current.modules)
		nextBucket := clonePersistentBucket(bucket)
		nextBucket[key] = value
		// The per-extension quota, checked before the write rather than
		// discovered at marshal time. The global bound is still enforced below;
		// this is what stops one extension from consuming it.
		if persistentBucketBytes(nextBucket) > maxPersistentModuleBytes {
			r.reportStorageQuota(moduleID, "extension storage quota exhausted")
			return vm.ToValue(false)
		}
		nextModules[moduleID] = nextBucket
		next := &persistentSnapshot{modules: nextModules}
		if err := r.persistPersistent(next); err != nil {
			// Previously indistinguishable from every other false this function
			// returns, and silent besides: an operator whose extension had
			// filled the store saw writes fail with nothing to explain why.
			r.reportStorageQuota(moduleID, err.Error())
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
		if !spend() {
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
		if !spend() {
			return vm.ToValue(false)
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
	if err := os.Rename(tempPath, r.statePath); err != nil {
		return err
	}
	// store.json is a sibling of meta.json and pointer.json, and bundleStore
	// writes those with "atomic rename + fsync of file and directory". This one
	// synced the file and skipped the directory, so the rename itself was not
	// durable: a power cut could leave the directory entry naming the old inode,
	// or a temp file that was then removed -- a storage.set that returned true to
	// a script silently undone, or the whole store absent on the first write.
	return syncBundleDir(filepath.Dir(r.statePath))
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
		// A Go string in the map is re-imported, and re-scanned for its unicode
		// shape, on every property read. Importing it once here is what the
		// binary branch below already does.
		object["body"] = vm.ToValue(string(message.Body))
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

// maxWireHeaderBytes bounds headers that arrived over the wire.
//
// This file does not enforce it: net/http already did, before the headers ever
// reached a script message. Both inbound servers set MaxHeaderBytes to it, and
// both upstream transports set MaxResponseHeaderBytes to it. Naming it makes
// the inbound bound explicit rather than an accident of whichever validator
// happened to run on the way past.
const maxWireHeaderBytes = maxModuleNetworkHeaderBytes

// wireHeaders projects headers that arrived over the wire into a script message.
//
// It deliberately does not run exportedHeaders. That function is the validator
// for what a *script* produces, and running it over inbound traffic conflated
// two jobs: net/http has already parsed these, so the names are valid tokens,
// the values carry no control characters, case-folded duplicates are merged
// under one canonical key, and the whole block is inside maxWireHeaderBytes.
//
// The conflation was not only wasted work on every intercepted exchange -- a
// sort, a case-fold map and a full rebuild -- it rejected legitimate traffic.
// exportedHeaders bounds field and value *counts* as well as bytes, and those
// counts are calibrated for what a script may invent, not for what an origin
// may send: a response with more than maxScriptHeaderFields fields was refused,
// and on the response path that refusal is a 502 for an exchange the origin
// answered perfectly well.
//
// The script budget still governs script output, which is where it belongs. A
// script that echoes a header block larger than that budget is refused there --
// by the limit written for it, rather than by an inbound check standing in.
func wireHeaders(source http.Header) http.Header {
	return cloneProxyHeaders(source)
}

// wireTrailers projects an origin's trailer block into a script message and,
// for the passthrough leg, into what gets republished.
//
// It is exportedTrailers minus one thing: the fatal check on names
// validResponseTrailerName rejects. That check is right for a script's output --
// a script inventing a Cache-Control trailer is a mistake worth refusing -- but
// three call sites were running it over the *origin's* block, where it means
// something else entirely. Those names are the RFC 7230 4.1.2 set a proxy MUST
// NOT forward in a trailer section; an origin that emits one is quirky, not
// hostile, and the correct proxy behaviour is to drop the field. Refusing turned
// it into a failed exchange: on the pure passthrough leg
// panic(http.ErrAbortHandler), tearing the client connection down before a byte
// was written, for a response this process was only relaying.
//
// responseTrailerNames and publishResponseTrailers already drop exactly these
// names one layer down, so dropping here loses nothing and additionally keeps
// the script's projection equal to what the runtime could put back on the wire.
//
// The count, value and duplicate-name bounds stay. Unlike a header block -- where
// those counts are calibrated for what a script invents and wrongly refused
// large but legitimate origin responses -- a trailer section is a handful of
// fields by construction, it arrives after the body so no transport header bound
// covers it, and TestStreamingResponseRejectsUnsafeTrailers pins them.
func wireTrailers(source http.Header) (http.Header, error) {
	trailers, err := exportedHeaders(source)
	if err != nil {
		return nil, err
	}
	for name := range trailers {
		if !validResponseTrailerName(name) {
			delete(trailers, name)
		}
	}
	return trailers, nil
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

// Match canonicalises value first. Use it for a host that has not already been
// through canonicalHost.
func (m *compiledHostMatcher) Match(value string) bool {
	if m == nil {
		return false
	}
	return m.matchCanonical(canonicalHost(value))
}

// matchCanonical is Match for a host the caller has already canonicalised.
//
// The rule walk canonicalises once and then called Match, which canonicalised
// again -- once per module and again per rule that passed the phase test. On a
// module set the size of a real catalogue that is around twenty redundant
// ToLower/TrimSpace/Contains/TrimSuffix passes over the same string per
// request, which is the same order as everything else the walk costs.
func (m *compiledHostMatcher) matchCanonical(host string) bool {
	if m == nil {
		return false
	}
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
			// A closed gate removes the action here rather than at match time:
			// it never becomes a compiledScriptRule, so nothing matches it and
			// no request pays for the check. validateActionGate has already
			// established that the named setting is a required boolean, so an
			// enabled module always has a value to read.
			if !actionGateOpen(rule, settings) {
				continue
			}
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
			// The jq artifact belongs to this generation for the same reason the
			// goja one does. Compiling here rather than threading a second map
			// out of validate is deliberate: the whole shipped corpus is under
			// 1.5 ms of jq compilation, and a generation is only built when the
			// document digest actually changed.
			if rule.JQProgram != "" {
				code, jqErr := compileJQProgram(rule.JQProgram)
				if jqErr != nil {
					return nil, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, jqErr)
				}
				rule.jq = code
			}
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
	return matchingScriptRulesWithStatus(cfg, phase, message, true)
}

// matchingScriptRulesWithStatus matches rules against message, treating
// message.StatusCode as known only when matchStatus is set.
//
// The request phase probes for response rules before any status exists, and
// there a rule constrained by status_codes has to count as a possible match
// rather than be dropped for failing to equal zero.
//
// The flag cannot be replaced by reading a zero StatusCode as "unknown": an
// origin answering "HTTP/1.1 000" gives net/http a response whose StatusCode is
// genuinely 0, and that value reaches the response-phase match. Inferring the
// phase from the value would run a status-scoped action on a response the
// operator wrote status_codes precisely to exclude.
func matchingScriptRulesWithStatus(cfg Config, phase string, message scriptMessage, matchStatus bool) []matchedScriptRule {
	parsed, err := url.Parse(message.URL)
	if err != nil {
		return nil
	}
	return matchingScriptRulesParsed(cfg, phase, message, matchStatus, parsed)
}

// matchingScriptRulesParsed is matchingScriptRulesWithStatus for a caller that
// has already parsed message.URL. Both request paths had, and then this parsed
// it again.
func matchingScriptRulesParsed(cfg Config, phase string, message scriptMessage, matchStatus bool, parsed *url.URL) []matchedScriptRule {
	var err error
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
		if !compiledModule.hosts.matchCanonical(host) {
			continue
		}
		for _, compiledRule := range compiledModule.rules {
			rule := compiledRule.rule
			if rule.Phase != phase || !compiledRule.hosts.matchCanonical(host) || !containsString(rule.Match.Schemes, scheme) {
				continue
			}
			if len(rule.Match.Methods) > 0 && !containsString(rule.Match.Methods, message.Method) {
				continue
			}
			if matchStatus && len(rule.Match.StatusCodes) > 0 && !containsInt(rule.Match.StatusCodes, message.StatusCode) {
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

// persistentBucketBytes measures one extension's stored bytes the way the
// global bound measures the whole store: keys plus values, without the JSON
// framing, which is close enough to compare against a quota and cheap enough to
// run on every write.
func persistentBucketBytes(bucket map[string]string) int {
	total := 0
	for key, value := range bucket {
		total += len(key) + len(value)
	}
	return total
}

// reportStorageQuota makes a refused write visible.
//
// storage.set answers false for a bad key, a value that is too long, an
// exhausted commit budget, a load failure and an exhausted quota alike, so a
// script cannot tell them apart -- and nothing was logged either. The quota
// cases are the ones an operator has to act on.
func (r *scriptRuntime) reportStorageQuota(moduleID, message string) {
	if !engineLogPublishingEnabled(r.logs) {
		return
	}
	r.logs.Publish(EngineLog{
		Level:     "warn",
		Source:    "engine",
		Extension: moduleID,
		Message:   "persistent storage write refused: " + message,
	})
}
