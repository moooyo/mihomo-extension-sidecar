package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// runCompatScript drives a script the way a published proxy-client bundle
// behaves: it returns immediately and signals completion by calling $done.
func runCompatScript(t *testing.T, source string, options compatOptions) (goja.Value, error) {
	t.Helper()
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	if err := loop.installTimerAPI(vm); err != nil {
		t.Fatal(err)
	}
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(source); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := loop.wait(ctx, entry.settled); err != nil {
		return nil, err
	}
	return entry.result, nil
}

func compatFixtureOptions() compatOptions {
	return compatOptions{
		request:   map[string]any{"url": "https://api.example.com/v1", "method": "GET", "headers": map[string]any{}},
		response:  map[string]any{"status": 200, "headers": map[string]any{}, "body": "ok"},
		argument:  `mode="clean"&level="2"`,
		startTime: time.Now(),
	}
}

func TestCompatPersonaResolvesToSurge(t *testing.T) {
	t.Parallel()
	// This is the same probe order @nsnanocat/util uses. Defining any of the
	// earlier globals would select the wrong branch and change the bundle's
	// network, storage, and completion shapes.
	source := `
const has = (name) => name in globalThis
let runtime
switch (true) {
  case has("$task"): runtime = "Quantumult X"; break
  case has("$loon"): runtime = "Loon"; break
  case has("$rocket"): runtime = "Shadowrocket"; break
  case has("Egern"): runtime = "Egern"; break
  case Boolean(globalThis.$environment?.["surge-version"]): runtime = "Surge"; break
  case Boolean(globalThis.$environment?.["stash-version"]): runtime = "Stash"; break
  default: runtime = "Node.js"
}
$done({ runtime, startTime: typeof $script.startTime })
`
	result, err := runCompatScript(t, source, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	exported, ok := stringAnyMap(result.Export())
	if !ok {
		t.Fatalf("result = %v, want an object", result)
	}
	if exported["runtime"] != "Surge" {
		t.Fatalf("runtime = %v, want Surge", exported["runtime"])
	}
	if exported["startTime"] != "number" {
		t.Fatalf("$script.startTime = %v, want a number", exported["startTime"])
	}
}

func TestCompatEntryCompletesThroughDoneAfterAwait(t *testing.T) {
	t.Parallel()
	// The bundle shape: an async IIFE that assigns back to $response and calls
	// $done from a .finally, with nothing returned to the host.
	source := `
(async () => {
  const suffix = await Promise.resolve("!")
  $response = { ...$response, body: $response.body + suffix }
})().finally(() => $done($response))
`
	result, err := runCompatScript(t, source, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	exported, ok := stringAnyMap(result.Export())
	if !ok {
		t.Fatalf("result = %v, want an object", result)
	}
	if exported["body"] != "ok!" {
		t.Fatalf("body = %v, want ok!", exported["body"])
	}
}

func TestCompatArgumentIsTheSerializedSettingString(t *testing.T) {
	t.Parallel()
	// The bundle runs its own parser over $argument, so the host supplies the
	// published sgmodule's string form rather than a decoded object.
	source := `$done({ argument: $argument, type: typeof $argument })`
	result, err := runCompatScript(t, source, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	if exported["type"] != "string" {
		t.Fatalf("$argument type = %v, want string", exported["type"])
	}
	if exported["argument"] != `mode="clean"&level="2"` {
		t.Fatalf("$argument = %v, want the serialized setting string", exported["argument"])
	}
}

func TestCompatDoneKeepsTheFirstResult(t *testing.T) {
	t.Parallel()
	source := `$done({ body: "first" }); $done({ body: "second" })`
	result, err := runCompatScript(t, source, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	if exported["body"] != "first" {
		t.Fatalf("body = %v, want the first $done result", exported["body"])
	}
}

func TestCompatPersistentStoreUsesValueFirstArgumentOrder(t *testing.T) {
	t.Parallel()
	runtime := newScriptRuntime(filepath.Join(t.TempDir(), "store.json"))
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	options := compatFixtureOptions()
	options.storage = runtime.storageObject(vm, "io.example.fixture")
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		t.Fatal(err)
	}
	// Surge's write takes the value before the key; reversing them would store
	// under the wrong name and silently lose every cached value.
	source := `
$persistentStore.write("cached-value", "cache-key")
$done({ readBack: $persistentStore.read("cache-key"), missing: $persistentStore.read("absent") })
`
	if _, err := vm.RunString(source); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := loop.wait(ctx, entry.settled); err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(entry.result.Export())
	if exported["readBack"] != "cached-value" {
		t.Fatalf("readBack = %v, want cached-value", exported["readBack"])
	}
	if exported["missing"] != nil {
		t.Fatalf("missing = %v, want null for an absent key", exported["missing"])
	}
}

func TestCompatRequestOptionsDropTransportHints(t *testing.T) {
	t.Parallel()
	// The native requester rejects unknown option keys. Bundles pass transport
	// hints the sidecar owns itself, so they are dropped rather than rejected.
	vm := goja.New()
	raw := vm.ToValue(map[string]any{
		"url":           "https://api.example.net/v1",
		"headers":       map[string]any{"Accept": "application/json"},
		"body":          "payload",
		"binary-mode":   true,
		"auto-redirect": true,
		"policy":        "DIRECT",
		"timeout":       30,
	})
	options, binary, err := compatRequestOptions(raw, "post")
	if err != nil {
		t.Fatal(err)
	}
	if !binary {
		t.Fatal("binary-mode must be reported to the caller")
	}
	for key := range options {
		switch key {
		case "url", "method", "headers", "body":
		default:
			t.Fatalf("option %q would be rejected by the native requester", key)
		}
	}
	if options["method"] != "POST" {
		t.Fatalf("method = %v, want POST", options["method"])
	}
}

func TestCompatRequestOptionsAcceptABareURL(t *testing.T) {
	t.Parallel()
	vm := goja.New()
	options, binary, err := compatRequestOptions(vm.ToValue("https://api.example.net/v1"), "get")
	if err != nil {
		t.Fatal(err)
	}
	if binary {
		t.Fatal("a bare url must not request binary mode")
	}
	if options["url"] != "https://api.example.net/v1" || options["method"] != "GET" {
		t.Fatalf("options = %v, want the url with a GET method", options)
	}
}

func TestProxyCompatBundleRunsThroughExecute(t *testing.T) {
	t.Parallel()
	// The published bundle shape end to end: async work, completion through
	// $done from a .finally, and a response projection rather than the native
	// {response: {...}} envelope.
	source := `
(async () => {
  const suffix = await Promise.resolve("!")
  $response = { ...$response, body: $response.body + suffix, headers: { "X-Compat": "1" }, status: 203 }
})().finally(() => $done($response))
`
	rule := nativeRuntimeRule(source, "response", "text")
	rule.Entry = scriptEntryProxyCompat
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "ok!" {
		t.Fatalf("body = %q, want %q", got, "ok!")
	}
	if result.StatusCode != 203 {
		t.Fatalf("status = %d, want 203", result.StatusCode)
	}
	if result.Headers.Get("X-Compat") != "1" {
		t.Fatalf("headers = %v, want X-Compat", result.Headers)
	}
}

func TestProxyCompatBundleThatNeverCompletesHitsTheDeadline(t *testing.T) {
	t.Parallel()
	source := `(async () => { await new Promise(() => {}) })()`
	rule := nativeRuntimeRule(source, "response", "text")
	rule.Entry = scriptEntryProxyCompat
	rule.TimeoutMS = 120
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	started := time.Now()
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response); err == nil {
		t.Fatal("expected a bundle that never calls $done to hit the action deadline")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("action took %s, want it bounded by the deadline", elapsed)
	}
}

func TestSerializeCompatArgumentIsStableAndBounded(t *testing.T) {
	t.Parallel()
	// The bundle parses this string itself, so separators inside a value would
	// let one setting inject another.
	argument := serializeCompatArgument(map[string]any{
		"mode":    `cle"an&injected="x`,
		"enabled": true,
		"level":   float64(2),
	})
	want := `enabled="true"&level="2"&mode="clean injected=x"`
	if argument != strings.ReplaceAll(want, " ", "") {
		t.Fatalf("argument = %q, want %q", argument, strings.ReplaceAll(want, " ", ""))
	}
}

func TestCompatResultUnwrapsAHostImportedBody(t *testing.T) {
	t.Parallel()
	// scriptMessageObject imports the body once as a goja value. A bundle that
	// hands $response straight back to $done returns that member unchanged, so
	// exporting the outer object leaves the body wrapped and the patch would be
	// rejected as neither a string nor a Uint8Array.
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	options := compatFixtureOptions()
	options.response = map[string]any{
		"status":  200,
		"headers": map[string]any{},
		"body":    vm.ToValue("imported"),
	}
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(`$done($response)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := loop.wait(ctx, entry.settled); err != nil {
		t.Fatal(err)
	}
	result, err := parseCompatScriptResult(entry.result, true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(result.Body); got != "imported" {
		t.Fatalf("body = %q, want %q", got, "imported")
	}
}
