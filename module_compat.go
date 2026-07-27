package main

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

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

func flatCompatHeaders(headers map[string][]string) map[string]string {
	flat := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			flat[name] = values[0]
		}
	}
	return flat
}
