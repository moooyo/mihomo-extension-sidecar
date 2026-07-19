package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeRuntimeRule(source string, phase string, bodyMode string) ScriptRule {
	return ScriptRule{
		ID: "action", Phase: phase,
		Match:        ActionMatch{Hosts: []string{"api.example.com"}, Schemes: []string{"https"}, PathRegex: "^/"},
		ScriptDigest: digestText(source), ScriptBody: source, BodyMode: bodyMode,
		TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
	}
}

func nativeRuntimeModule() Module {
	return Module{ID: "io.example.fixture", CaptureHosts: []string{"api.example.com"}}
}

func TestNativeScriptTransformsResponseFromTypedContext(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  return { response: { status: 201, headers: {"X-Mode": context.settings.mode}, body: context.response.body + "!" } }
}`
	module := nativeRuntimeModule()
	module.Settings = []ModuleSetting{{Key: "mode", Type: "text", Required: true, Value: json.RawMessage(`"clean"`)}}
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	result, err := newScriptRuntime().execute(module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedBody || string(result.Body) != "ok!" || result.StatusCode != 201 || result.Headers.Get("X-Mode") != "clean" {
		t.Fatalf("native result = %+v", result)
	}
}

func TestNativeScriptSupportsBinaryBodies(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  const input = context.response.body
  return { response: { body: new Uint8Array([input[2], input[1], input[0]]) } }
}`
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte{1, 2, 3}}
	result, err := newScriptRuntime().execute(nativeRuntimeModule(), nativeRuntimeRule(source, "response", "binary"), request, &response)
	if err != nil || !bytes.Equal(result.Body, []byte{3, 2, 1}) {
		t.Fatalf("binary result=%+v err=%v", result, err)
	}
}

func TestNativeScriptRejectsAmbientNetworkAndTimesOut(t *testing.T) {
	t.Parallel()
	request := scriptMessage{URL: "https://api.example.com/v1", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	networked := `function transform() { return fetch("https://example.com/") }`
	if _, err := newScriptRuntime().execute(nativeRuntimeModule(), nativeRuntimeRule(networked, "response", "none"), request, &response); err == nil {
		t.Fatal("ambient network API was available")
	}
	timeout := nativeRuntimeRule(`function transform() { while (true) {} }`, "response", "none")
	timeout.TimeoutMS = 50
	started := time.Now()
	if _, err := newScriptRuntime().execute(nativeRuntimeModule(), timeout, request, &response); err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout result err=%v duration=%s", err, time.Since(started))
	}
}

func TestNativePersistentStorageRequiresManifestPermission(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	source := `function transform(context) {
  const previous = context.storage.get("counter")
  context.storage.set("counter", previous == null ? "1" : "2")
  return { response: { body: previous == null ? "empty" : previous } }
}`
	module := nativeRuntimeModule()
	module.PersistentStorage = true
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	first := newScriptRuntime(statePath)
	result, err := first.execute(module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "empty" {
		t.Fatalf("first store result=%q err=%v", result.Body, err)
	}
	second := newScriptRuntime(statePath)
	result, err = second.execute(module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "1" {
		t.Fatalf("persisted store result=%q err=%v", result.Body, err)
	}
	module.PersistentStorage = false
	if _, err := second.execute(module, nativeRuntimeRule(source, "response", "text"), request, &response); err == nil {
		t.Fatal("storage API was exposed without permission")
	}
}

func TestNativeActionMatchingIsScopedToExtensionCaptureHosts(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	cfg := Config{Modules: []Module{module}}
	inside := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	outside := scriptMessage{URL: "https://other.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	if len(matchingScriptRules(cfg, "response", inside)) != 1 || len(matchingScriptRules(cfg, "response", outside)) != 0 {
		t.Fatal("native action escaped its extension capture host boundary")
	}
}

func TestRepositoryWLOCExtensionScriptPatchesBinaryResponse(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile(filepath.Join("..", "..", "extensions", "apple-wloc", "wloc.js"))
	if err != nil {
		t.Fatal(err)
	}
	location := append(testVarintField(1, 1), testVarintField(2, 2)...)
	location = append(location, testVarintField(3, 99)...)
	wifi := testLengthField(1, []byte("aa:bb:cc:dd:ee:ff"))
	wifi = append(wifi, testLengthField(2, location)...)
	root := testLengthField(2, wifi)
	frame := append(make([]byte, 8), byte(len(root)>>8), byte(len(root)))
	frame = append(frame, root...)

	module := Module{
		ID: "io.5gpn.apple-wloc", CaptureHosts: []string{"gs-loc.apple.com"},
		Settings: []ModuleSetting{
			{Key: "location", Type: "location", Required: true, Value: json.RawMessage(`{"longitude":-122.4194,"latitude":37.7749,"accuracy":25}`)},
			{Key: "failClosed", Type: "boolean", Required: true, Value: json.RawMessage(`true`)},
		},
	}
	rule := ScriptRule{
		ID: "rewrite-wloc-response", Phase: "response",
		Match:        ActionMatch{Hosts: []string{"gs-loc.apple.com"}, Schemes: []string{"https"}, PathRegex: "^/clls/wloc$", StatusCodes: []int{200}},
		ScriptDigest: digestText(string(source)), ScriptBody: string(source), BodyMode: "binary", TimeoutMS: 1500, MaxBodyBytes: 8 << 20,
	}
	request := scriptMessage{URL: "https://gs-loc.apple.com/clls/wloc", Method: http.MethodPost, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, Method: request.Method, StatusCode: 200, Headers: make(http.Header), Body: frame}
	result, err := newScriptRuntime().execute(module, rule, request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedBody || bytes.Equal(result.Body, frame) || !strings.Contains(string(source), "function transform(context)") {
		t.Fatalf("WLOC native extension did not patch the response: %+v", result)
	}
}

func testEncodeVarint(value uint64) []byte {
	var output []byte
	for value >= 0x80 {
		output = append(output, byte(value)|0x80)
		value >>= 7
	}
	return append(output, byte(value))
}

func testVarintField(number, value uint64) []byte {
	return append(testEncodeVarint(number<<3), testEncodeVarint(value)...)
}

func testLengthField(number uint64, value []byte) []byte {
	output := testEncodeVarint(number<<3 | 2)
	output = append(output, testEncodeVarint(uint64(len(value)))...)
	return append(output, value...)
}
