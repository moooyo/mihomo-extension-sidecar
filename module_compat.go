package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// scriptEntryProxyCompat selects the published proxy-client bundle contract
// instead of the native transform(context) entry point.
const scriptEntryProxyCompat = "proxy-compat"

// surgePersonaVersion is reported through $environment["surge-version"].
//
// @nsnanocat/util picks its runtime by probing globals in a fixed order:
// $task, $loon, $rocket, Egern, then $environment["surge-version"]. Presenting
// as Surge is what lets a published bundle take a code path whose network and
// storage shapes map onto capabilities this sidecar already has. It is a
// compatibility persona, not a claim to be Surge, so none of the earlier
// globals may be defined or the bundle selects the wrong branch.
const surgePersonaVersion = "5.0.0"

// compatOptions carries everything one compat-mode action needs. Every field is
// produced by the existing native plumbing; nothing here is a second
// implementation of storage, settings, or networking.
type compatOptions struct {
	request   map[string]any
	response  map[string]any
	argument  string
	storage   *goja.Object
	requester *moduleNetworkRequester
	startTime time.Time
}

// compatEntry tracks completion for a bundle that signals it by calling $done
// rather than by returning a value.
type compatEntry struct {
	completed bool
	result    goja.Value
}

func (c *compatEntry) settled() bool { return c.completed }

// installProxyCompatAPI defines the globals a published proxy-client bundle
// expects and returns the completion tracker the event loop waits on.
func installProxyCompatAPI(vm *goja.Runtime, loop *asyncLoop, options compatOptions) (*compatEntry, error) {
	entry := &compatEntry{}

	environment := vm.NewObject()
	if err := environment.Set("surge-version", surgePersonaVersion); err != nil {
		return nil, err
	}
	if err := vm.Set("$environment", environment); err != nil {
		return nil, err
	}

	// The Surge completion branch reads $script.startTime before calling $done.
	// A TypeError there would be swallowed by the bundle's .finally() and the
	// action would hang until its deadline instead of failing.
	script := vm.NewObject()
	if err := script.Set("startTime", float64(options.startTime.UnixNano())/float64(time.Second)); err != nil {
		return nil, err
	}
	if err := vm.Set("$script", script); err != nil {
		return nil, err
	}

	if err := vm.Set("$request", options.request); err != nil {
		return nil, err
	}
	// The bundle assigns back to $response, so it must exist even for a request
	// action, where it stays undefined rather than absent.
	if options.response != nil {
		if err := vm.Set("$response", options.response); err != nil {
			return nil, err
		}
	} else if err := vm.Set("$response", goja.Undefined()); err != nil {
		return nil, err
	}

	if err := vm.Set("$argument", options.argument); err != nil {
		return nil, err
	}

	// First call wins. A bundle that calls $done twice would otherwise be able
	// to replace an already-observed result.
	if err := vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		if entry.completed {
			return goja.Undefined()
		}
		entry.completed = true
		entry.result = call.Argument(0)
		return goja.Undefined()
	}); err != nil {
		return nil, err
	}

	if options.storage != nil {
		store, err := compatPersistentStore(vm, options.storage)
		if err != nil {
			return nil, err
		}
		if err := vm.Set("$persistentStore", store); err != nil {
			return nil, err
		}
	}

	if options.requester != nil {
		client, err := compatHTTPClient(vm, loop, options.requester)
		if err != nil {
			return nil, err
		}
		if err := vm.Set("$httpClient", client); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

// compatPersistentStore adapts the bounded native storage object to the
// read/write pair the bundles use. Note the argument order: write takes the
// value first.
func compatPersistentStore(vm *goja.Runtime, storage *goja.Object) (*goja.Object, error) {
	get, ok := goja.AssertFunction(storage.Get("get"))
	if !ok {
		return nil, errors.New("storage object has no get function")
	}
	set, ok := goja.AssertFunction(storage.Get("set"))
	if !ok {
		return nil, errors.New("storage object has no set function")
	}
	store := vm.NewObject()
	if err := store.Set("read", func(call goja.FunctionCall) goja.Value {
		value, err := get(goja.Undefined(), call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return value
	}); err != nil {
		return nil, err
	}
	if err := store.Set("write", func(call goja.FunctionCall) goja.Value {
		value, err := set(goja.Undefined(), call.Argument(1), call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return value
	}); err != nil {
		return nil, err
	}
	return store, nil
}

// compatHTTPClient exposes the Surge-style callback network API. The blocking
// request runs on a worker goroutine and its completion is posted back to the
// goroutine that owns the VM, because goja is not goroutine-safe.
func compatHTTPClient(vm *goja.Runtime, loop *asyncLoop, requester *moduleNetworkRequester) (*goja.Object, error) {
	calls := 0
	client := vm.NewObject()
	for _, method := range []string{"get", "post", "put", "delete", "head", "patch"} {
		if err := client.Set(method, compatHTTPMethod(vm, loop, requester, method, &calls)); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func compatHTTPMethod(
	vm *goja.Runtime,
	loop *asyncLoop,
	requester *moduleNetworkRequester,
	method string,
	calls *int,
) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		*calls++
		if *calls > maxModuleNetworkCallsPerAction {
			panic(vm.NewGoError(errors.New("network request limit exceeded")))
		}
		callback, ok := goja.AssertFunction(call.Argument(1))
		if !ok {
			panic(vm.NewTypeError("$httpClient." + method + " requires a callback"))
		}
		options, binary, err := compatRequestOptions(call.Argument(0), method)
		if err != nil {
			panic(vm.NewTypeError(err.Error()))
		}

		go func() {
			response, requestErr := requester.request(options)
			loop.post(func() error {
				if requestErr != nil {
					_, callErr := callback(goja.Undefined(), vm.ToValue(requestErr.Error()))
					return callErr
				}
				projection := map[string]any{
					"status":  response.status,
					"headers": flatCompatHeaders(response.headers),
				}
				body, bodyErr := compatResponseBody(vm, response.body, binary)
				if bodyErr != nil {
					_, callErr := callback(goja.Undefined(), vm.ToValue(bodyErr.Error()))
					return callErr
				}
				_, callErr := callback(goja.Undefined(), goja.Null(), vm.ToValue(projection), body)
				return callErr
			})
		}()
		return goja.Undefined()
	}
}

// compatRequestOptions narrows a bundle's request options to the four keys the
// native requester accepts. The bundles also pass transport hints such as
// binary-mode, auto-redirect, policy, and timeout; those are runtime-owned here
// and are dropped rather than rejected, so a bundle is not broken by a hint the
// sidecar simply does not delegate.
func compatRequestOptions(raw goja.Value, method string) (map[string]any, bool, error) {
	options := map[string]any{"method": methodToken(method)}
	if raw == nil || goja.IsUndefined(raw) || goja.IsNull(raw) {
		return nil, false, errors.New("$httpClient requires a url or options object")
	}
	if url, ok := raw.Export().(string); ok {
		options["url"] = url
		return options, false, nil
	}
	source, ok := stringAnyMap(raw.Export())
	if !ok {
		return nil, false, errors.New("$httpClient requires a url string or options object")
	}
	for _, key := range []string{"url", "headers", "body"} {
		if value, exists := source[key]; exists {
			options[key] = value
		}
	}
	if _, exists := options["url"]; !exists {
		return nil, false, errors.New("$httpClient options must contain a url")
	}
	binary := false
	if value, exists := source["binary-mode"]; exists {
		enabled, _ := value.(bool)
		binary = enabled
	}
	return options, binary, nil
}

func methodToken(method string) string {
	switch method {
	case "get":
		return "GET"
	case "post":
		return "POST"
	case "put":
		return "PUT"
	case "delete":
		return "DELETE"
	case "head":
		return "HEAD"
	case "patch":
		return "PATCH"
	default:
		return "GET"
	}
}

// compatResponseBody returns a Uint8Array when the caller asked for binary mode
// or the payload is not valid UTF-8, and a string otherwise, matching what the
// bundles expect to receive as the callback's third argument.
func compatResponseBody(vm *goja.Runtime, body []byte, binary bool) (goja.Value, error) {
	if !binary && utf8.Valid(body) {
		return vm.ToValue(string(body)), nil
	}
	value, err := newModuleNetworkByteArray(vm, body)
	if err != nil {
		return nil, fmt.Errorf("response body could not be projected: %w", err)
	}
	return value, nil
}

// executeProxyCompat runs a published proxy-client bundle. The bundle returns
// immediately, leaves work pending on the event loop, and signals completion by
// calling $done, so the action waits on that rather than on a returned value.
func (r *scriptRuntime) executeProxyCompat(
	ctx context.Context,
	vm *goja.Runtime,
	loop *asyncLoop,
	program *goja.Program,
	module Module,
	rule ScriptRule,
	settings map[string]any,
	requestObject map[string]any,
	contextObject map[string]any,
	requester *moduleNetworkRequester,
	responsePhase bool,
) (scriptResult, error) {
	options := compatOptions{
		request:   requestObject,
		argument:  serializeCompatArgument(settings),
		startTime: time.Now(),
		requester: requester,
	}
	if responseObject, ok := contextObject["response"].(map[string]any); ok {
		options.response = responseObject
	}
	if storage, ok := contextObject["storage"].(*goja.Object); ok {
		options.storage = storage
	}
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	if _, err := vm.RunProgram(program); err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	if err := loop.wait(ctx, entry.settled); err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	return parseCompatScriptResult(entry.result, responsePhase)
}

// serializeCompatArgument renders typed settings into the key="value" string
// the published sgmodule passes, because the bundle runs its own parser over it
// rather than accepting a decoded object.
func serializeCompatArgument(settings map[string]any) string {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		if builder.Len() > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(key)
		builder.WriteString(`="`)
		builder.WriteString(compatArgumentValue(settings[key]))
		builder.WriteString(`"`)
	}
	return builder.String()
}

func compatArgumentValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.NewReplacer(`"`, "", "&", "", "\r", "", "\n", "").Replace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return strings.NewReplacer(`"`, "", "&", "").Replace(string(encoded))
	}
}

// unwrapCompatValue exports a value that is still a goja value. The host hands
// the bundle a $response whose body was imported once as a goja value, and a
// bundle that passes that object straight back to $done returns the member
// unchanged, so exporting the outer object leaves it wrapped.
func unwrapCompatValue(raw any) any {
	if value, ok := raw.(goja.Value); ok {
		return value.Export()
	}
	return raw
}

func flatCompatHeaders(headers map[string][]string) map[string]string {
	flat := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			flat[name] = values[0]
		}
	}
	return flat
}

// parseCompatScriptResult converts the value handed to $done into an action
// result. A bundle passes the response projection itself rather than the
// {response: {...}} envelope the native contract uses, so the value is treated
// as the patch. `bodyBytes` is accepted alongside `body` because the bundles
// mirror a binary payload into both fields.
func parseCompatScriptResult(value goja.Value, responsePhase bool) (scriptResult, error) {
	result := scriptResult{}
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return result, nil
	}
	patch, ok := stringAnyMap(value.Export())
	if !ok {
		return result, errors.New("$done requires an object, null, or undefined")
	}
	projection := make(map[string]any, len(patch))
	for key, raw := range patch {
		switch key {
		case "status", "headers", "body", "trailers":
			projection[key] = unwrapCompatValue(raw)
		case "bodyBytes":
			// body wins when a bundle sets both, matching how the util mirrors
			// a binary payload before completing.
			if _, exists := projection["body"]; !exists {
				projection["body"] = unwrapCompatValue(raw)
			}
		case "statusCode":
			if _, exists := projection["status"]; !exists {
				projection["status"] = unwrapCompatValue(raw)
			}
		default:
			// Bundles carry transport hints such as policy or url through the
			// same object. They are runtime-owned here, so they are ignored
			// rather than failing the action.
		}
	}
	if body, exists := projection["body"]; exists && body == nil {
		delete(projection, "body")
	}
	if err := applyNativePatch(&result, projection, responsePhase); err != nil {
		return scriptResult{}, err
	}
	return result, nil
}
