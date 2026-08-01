package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// scriptEntryProxyCompat selects the published proxy-client bundle contract
// instead of the native transform(context) entry point.
const scriptEntryProxyCompat = "proxy-compat"

// loonPersonaVersion is reported through $loon.
//
// Published bundles probe for a client in a fixed order -- $task, $loon,
// $rocket, Egern, then $environment["surge-version"] -- and take a different
// branch for each. Loon is the branch this runtime presents, because Loon is
// also the publishing convention this repository follows: its [Argument]
// section is typed, matching the manifest's typed settings, and it hands the
// bundle $argument as a decoded object rather than a string each publisher
// encodes differently. It is a compatibility persona, not a claim to be Loon,
// so $task must stay undefined or a bundle selects Quantumult X instead.
const loonPersonaVersion = "3.3.8(932)"

// compatOptions carries everything one compat-mode action needs. Every field is
// produced by the existing native plumbing; nothing here is a second
// implementation of storage, settings, or networking.
type compatOptions struct {
	request         map[string]any
	response        map[string]any
	argument        map[string]any
	storage         *goja.Object
	requester       *moduleNetworkRequester
	startTime       time.Time
	decompressLimit int64
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

	if err := vm.Set("$loon", loonPersonaVersion); err != nil {
		return nil, err
	}
	// Some bundles read $environment even on the Loon branch, for a build or
	// language hint. It exists and reports Loon rather than being absent, which
	// would throw on the property read.
	environment := vm.NewObject()
	if err := environment.Set("loon-version", loonPersonaVersion); err != nil {
		return nil, err
	}
	if err := vm.Set("$environment", environment); err != nil {
		return nil, err
	}

	// The completion branch reads $script.startTime before calling $done, on
	// Loon as well as the personas this runtime does not serve.
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

	// Loon hands the bundle a decoded object. Every encoding bug this layer hit
	// -- weatherkit's quoted form, bilibili's and youtube's JSON, wloc's bare
	// query -- came from serializing settings into a string each publisher then
	// parsed differently, and a bundle that mis-parses $argument does not fail,
	// it silently runs on its defaults.
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

	// $persistentStore is referenced unconditionally by the bundles' storage
	// layer, so it always exists. Without the storage permission it is a
	// truthful null store — reads miss and writes report failure — rather than
	// an undefined global that throws inside the bundle's own catch and makes
	// the action look like it simply chose not to transform anything.
	store, err := compatPersistentStore(vm, options.storage)
	if err != nil {
		return nil, err
	}
	if err := vm.Set("$persistentStore", store); err != nil {
		return nil, err
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

	// $utils.ungzip is a host-provided decompressor. The gRPC middleware in the
	// published Bilibili bundle reaches it on every persona, not just Loon's, so
	// leaving it undefined would throw inside the bundle's own error handling and
	// surface as an action that simply declined to transform anything.
	utils, err := compatUtils(vm, options.decompressLimit)
	if err != nil {
		return nil, err
	}
	if err := vm.Set("$utils", utils); err != nil {
		return nil, err
	}

	// The gateway has no channel to deliver an operator notification on, so this
	// records the call through the action's own console budget rather than
	// pretending to deliver it. It has to exist: the bundles call it from their
	// error and status paths.
	notification := vm.NewObject()
	if err := notification.Set("post", func(call goja.FunctionCall) goja.Value {
		compatLogNotification(vm, call)
		return goja.Undefined()
	}); err != nil {
		return nil, err
	}
	if err := vm.Set("$notification", notification); err != nil {
		return nil, err
	}
	return entry, nil
}

// compatUtils provides the host helpers a published bundle expects to find on
// $utils. Only ungzip is implemented; anything else stays absent so a bundle
// reaching for an unimplemented helper fails loudly here rather than silently
// producing a wrong result.
func compatUtils(vm *goja.Runtime, limit int64) (*goja.Object, error) {
	utils := vm.NewObject()
	if err := utils.Set("ungzip", func(call goja.FunctionCall) goja.Value {
		body, err := exportedBody(call.Argument(0).Export())
		if err != nil {
			panic(vm.NewTypeError("ungzip expects a string or Uint8Array: %s", err))
		}
		// Bounded by the action's own body budget: a gzip bomb inside an
		// otherwise-conforming response must not outlive the limit the operator
		// already agreed to for this action.
		decoded, err := decodeContentBody(body, "gzip", limit)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		constructor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
		if !ok {
			panic(vm.NewTypeError("Uint8Array constructor is unavailable"))
		}
		value, err := constructor(nil, vm.ToValue(vm.NewArrayBuffer(decoded)))
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return value
	}); err != nil {
		return nil, err
	}
	return utils, nil
}

// compatNotificationText flattens $notification.post(title, subtitle, body, ...)
// into one log line. Only the three text arguments are recorded; the options
// object carries actions this runtime cannot perform anyway.
func compatNotificationText(call goja.FunctionCall) string {
	parts := make([]string, 0, 3)
	for index := 0; index < 3 && index < len(call.Arguments); index++ {
		argument := call.Argument(index)
		if goja.IsUndefined(argument) || goja.IsNull(argument) {
			continue
		}
		if text := strings.TrimSpace(argument.String()); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " — ")
}

// compatLogNotification routes a notification through the action's own console,
// so it inherits the per-action message cap and truncation already in place
// instead of opening a second, unbounded path to the engine log.
func compatLogNotification(vm *goja.Runtime, call goja.FunctionCall) {
	console, ok := vm.Get("console").(*goja.Object)
	if !ok {
		return
	}
	info, ok := goja.AssertFunction(console.Get("info"))
	if !ok {
		return
	}
	_, _ = info(console, vm.ToValue("$notification.post"), vm.ToValue(compatNotificationText(call)))
}

// compatPersistentStore adapts the bounded native storage object to the
// read/write pair the bundles use. Note the argument order: write takes the
// value first. A nil storage object means the extension has no storage
// permission, and the store reports that honestly instead of being absent.
func compatPersistentStore(vm *goja.Runtime, storage *goja.Object) (*goja.Object, error) {
	store := vm.NewObject()
	if storage == nil {
		if err := store.Set("read", func(goja.FunctionCall) goja.Value { return goja.Null() }); err != nil {
			return nil, err
		}
		if err := store.Set("write", func(goja.FunctionCall) goja.Value { return vm.ToValue(false) }); err != nil {
			return nil, err
		}
		return store, nil
	}
	get, ok := goja.AssertFunction(storage.Get("get"))
	if !ok {
		return nil, errors.New("storage object has no get function")
	}
	set, ok := goja.AssertFunction(storage.Get("set"))
	if !ok {
		return nil, errors.New("storage object has no set function")
	}
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

// compatHTTPClient exposes the callback network API $httpClient names on Loon. The blocking
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
		request:         requestObject,
		argument:        settings,
		startTime:       time.Now(),
		requester:       requester,
		decompressLimit: rule.MaxBodyBytes,
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
	if compatProjectionIsEmpty(entry.result) && engineLogPublishingEnabled(r.logs) {
		r.logs.Publish(EngineLog{
			Level: "warn", Source: "engine", Extension: module.ID, Action: rule.ID,
			Phase: rule.Phase, URL: sanitizeEngineLogURL(request(contextObject)),
			ScriptDigest: rule.ScriptDigest,
			Message:      "bundle completed with no member this runtime understands; the action changed nothing",
		})
	}
	return parseCompatScriptResult(entry.result, responsePhase)
}

// request reads the URL out of the projection handed to the bundle, for the
// engine log only.
func request(contextObject map[string]any) string {
	message, ok := contextObject["request"].(map[string]any)
	if !ok {
		return ""
	}
	url, _ := message["url"].(string)
	return url
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

// parseCompatScriptResult translates the value a bundle handed $done.
//
// A Loon completion wraps the projection in a `response` envelope. The shipped
// wloc bundle ends with, after minification:
//
//	"Quantumult X" === client ? done(out) : done({response: out})
//
// and this runtime presents as Loon precisely so it takes the second branch --
// so the envelope is the shape it should have expected all along, not an
// exception. Ignoring it made both apple-wloc actions permanent silent no-ops:
// the projection came out empty, no error was raised, and the device's real
// location was forwarded whatever point an operator had configured. That is the
// failure docs/proxy-compat.md predicted, where a gap "will look like the bundle
// chose not to act, not like a crash".
//
// The native contract has always handled this shape (parseNativeScriptResult),
// including turning a request-phase `response` into a synthetic reply, so the
// envelope is unwrapped here with the same meaning rather than a parallel one.
func parseCompatScriptResult(value goja.Value, responsePhase bool) (scriptResult, error) {
	result := scriptResult{}
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return result, nil
	}
	patch, ok := stringAnyMap(value.Export())
	if !ok {
		return result, errors.New("$done requires an object, null, or undefined")
	}
	if envelope, wrapped := patch["response"]; wrapped {
		projection, ok := stringAnyMap(unwrapCompatValue(envelope))
		if !ok {
			return scriptResult{}, errors.New("$done response envelope must be an object")
		}
		if err := applyNativePatch(&result, compatProjection(projection), true); err != nil {
			return scriptResult{}, err
		}
		// A request-phase action that completes with a response is answering the
		// exchange itself, which is what save-wloc-settings does to return its
		// stored point as JSON.
		result.Synthetic = !responsePhase
		return result, nil
	}
	return result, applyNativePatch(&result, compatProjection(patch), responsePhase)
}

// compatProjection keeps the members the runtime owns and drops the rest.
//
// A bundle carries transport hints -- policy, node, url -- through the same
// object, and the Loon branch of every published util sets them, so an unknown
// member cannot be an error the way it is on the native contract. What can be
// reported is a completion that carried nothing at all: see
// compatProjectionIsEmpty.
func compatProjection(patch map[string]any) map[string]any {
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
		}
	}
	if body, exists := projection["body"]; exists && body == nil {
		delete(projection, "body")
	}
	return projection
}

// compatProjectionIsEmpty reports a completion this runtime understood nothing
// of. It is the signature of the bug this envelope handling fixed, so it is
// reported rather than left for the next reader to rediscover from traffic.
func compatProjectionIsEmpty(value goja.Value) bool {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return false
	}
	patch, ok := stringAnyMap(value.Export())
	if !ok || len(patch) == 0 {
		return false
	}
	// Recurse rather than short-circuit. parseCompatScriptResult runs the
	// envelope's inner object through the same compatProjection filter, so an
	// envelope whose inner members are all transport hints is exactly the empty
	// projection this detector exists to report -- and returning false here made
	// it the one shape it refused to look inside, leaving the apple-wloc failure
	// mode (a permanent silent no-op with no error and no warning) undiagnosable
	// through the engine log ring.
	//
	// Two sub-cases stay unreported, matching the flat path's own conventions: a
	// non-object inner already fails loudly at parse, so warning first would only
	// add noise ahead of an error, and an empty inner mirrors the deliberate
	// exemption len(patch) == 0 gives the flat $done({}).
	if envelope, wrapped := patch["response"]; wrapped {
		inner, ok := stringAnyMap(unwrapCompatValue(envelope))
		if !ok || len(inner) == 0 {
			return false
		}
		return len(compatProjection(inner)) == 0
	}
	return len(compatProjection(patch)) == 0
}
