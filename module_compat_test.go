package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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
	}, compatArgumentFormatQuery)
	want := `enabled="true"&level="2"&mode="clean injected=x"`
	if argument != strings.ReplaceAll(want, " ", "") {
		t.Fatalf("argument = %q, want %q", argument, strings.ReplaceAll(want, " ", ""))
	}
}

func TestSerializeCompatArgumentDefaultsToTheQueryForm(t *testing.T) {
	t.Parallel()
	// weatherkit is already published against the query form, so an action that
	// declares no format must keep receiving it.
	settings := map[string]any{"enabled": true}
	if got := serializeCompatArgument(settings, ""); got != `enabled="true"` {
		t.Fatalf("argument = %q, want the query form by default", got)
	}
}

func TestSerializeCompatArgumentJSONKeepsDeclaredTypes(t *testing.T) {
	t.Parallel()
	// The bundles hand this to JSON.parse and then compare values. A boolean
	// rendered as the string "true" survives a truthiness test but fails ===,
	// so the types have to cross intact rather than being stringified.
	argument := serializeCompatArgument(map[string]any{
		"enabled": true,
		"level":   float64(2),
		"mode":    "clean",
	}, compatArgumentFormatJSON)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
		t.Fatalf("argument %q is not JSON the bundle could parse: %v", argument, err)
	}
	if decoded["enabled"] != true || decoded["level"] != float64(2) || decoded["mode"] != "clean" {
		t.Fatalf("decoded = %#v, want the declared types preserved", decoded)
	}
}

func TestSerializeCompatArgumentJSONIsAnObjectWhenEmpty(t *testing.T) {
	t.Parallel()
	// An extension with no settings still has its $argument passed to
	// JSON.parse. An empty string would throw there, inside a bundle that
	// swallows the failure and silently runs on defaults.
	if got := serializeCompatArgument(nil, compatArgumentFormatJSON); got != "{}" {
		t.Fatalf("argument = %q, want an empty object", got)
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

func TestCompatPersistentStoreExistsWithoutTheStoragePermission(t *testing.T) {
	t.Parallel()
	// The bundles' storage layer references $persistentStore unconditionally.
	// An undefined global throws inside their own catch, and the action then
	// completes with the response untouched — which reads as "the bundle chose
	// not to transform anything" rather than as a failure.
	options := compatFixtureOptions()
	options.storage = nil
	result, err := runCompatScript(t, `$done({
  body: JSON.stringify({
    read: $persistentStore.read("k"),
    wrote: $persistentStore.write("v", "k"),
  }),
})`, options)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	if exported["body"] != `{"read":null,"wrote":false}` {
		t.Fatalf("null store reported %v, want a miss and a failed write", exported["body"])
	}
}

// compatUngzipFixture runs a compat script with gzipped bytes already in
// $request.body, which is how the Bilibili bundle's gRPC middleware meets them.
func compatUngzipFixture(t *testing.T, payload []byte, limit int64, source string) (goja.Value, error) {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	constructor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
	if !ok {
		t.Fatal("Uint8Array constructor is unavailable")
	}
	body, err := constructor(nil, vm.ToValue(vm.NewArrayBuffer(compressed.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	options := compatFixtureOptions()
	options.request = map[string]any{"url": "https://api.example.com/v1", "body": body}
	options.decompressLimit = limit
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

func TestCompatUtilsUngzipReturnsTheOriginalBytes(t *testing.T) {
	t.Parallel()
	// The published Bilibili bundle reaches $utils.ungzip from its gRPC
	// middleware on every persona, so an undefined $utils would throw inside its
	// own error handling and read as an action that declined to transform.
	payload := []byte("the original gRPC frame payload")
	result, err := compatUngzipFixture(t, payload, 1<<20, `
	  const out = $utils.ungzip($request.body)
	  $done({ body: String(out instanceof Uint8Array) + ":" + String.fromCharCode.apply(null, out) })
	`)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCompatScriptResult(result, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(parsed.Body), "true:"+string(payload); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestCompatUtilsUngzipStaysInsideTheActionBudget(t *testing.T) {
	t.Parallel()
	// A compressed body that expands past the limit the operator already agreed
	// to for this action must fail rather than be decompressed anyway.
	result, err := compatUngzipFixture(t, bytes.Repeat([]byte("a"), 512<<10), 4096, `
	  try { $utils.ungzip($request.body); $done({ body: "unbounded" }) }
	  catch (error) { $done({ body: "bounded" }) }
	`)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCompatScriptResult(result, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Body) != "bounded" {
		t.Fatalf("body = %q, want the decompression refused by the action budget", parsed.Body)
	}
}
func TestCompatNotificationIsDefinedAndRoutesToConsole(t *testing.T) {
	t.Parallel()
	// Both published bundles call $notification.post from their Surge error and
	// status paths. Leaving it undefined throws inside the bundle's own catch,
	// which then still calls $done — the failure looks like a silent no-op.
	result, err := runCompatScript(t, `
	  const seen = []
	  console = { info: function () { seen.push(Array.prototype.join.call(arguments, " ")) } }
	  $notification.post("Bilibili", "airborne", "3 segments", { "auto-dismiss": 5 })
	  $done({ body: seen.join("|") })
	`, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCompatScriptResult(result, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(parsed.Body), "$notification.post Bilibili — airborne — 3 segments"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestCompatNotificationSurvivesWithoutAConsole(t *testing.T) {
	t.Parallel()
	// The console is installed by the runtime, not by this layer. If it is ever
	// absent the notification must be dropped, not turned into a throw on the
	// bundle's error path.
	result, err := runCompatScript(t, `
	  $notification.post("title")
	  $done({ body: "survived" })
	`, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCompatScriptResult(result, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Body) != "survived" {
		t.Fatalf("body = %q, want the notification dropped silently", parsed.Body)
	}
}
