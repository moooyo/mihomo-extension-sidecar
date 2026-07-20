package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
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
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
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
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(source, "response", "binary"), request, &response)
	if err != nil || !bytes.Equal(result.Body, []byte{3, 2, 1}) {
		t.Fatalf("binary result=%+v err=%v", result, err)
	}
}

func TestNativeScriptRejectsAmbientNetworkAndTimesOut(t *testing.T) {
	t.Parallel()
	request := scriptMessage{URL: "https://api.example.com/v1", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	networked := `function transform() { return fetch("https://example.com/") }`
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(networked, "response", "none"), request, &response); err == nil {
		t.Fatal("ambient network API was available")
	}
	capabilityProbe := `function transform(context) { return {response: {body: typeof context.network}} }`
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(capabilityProbe, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "undefined" {
		t.Fatalf("undeclared network capability result=%q err=%v", result.Body, err)
	}
	timeout := nativeRuntimeRule(`function transform() { while (true) {} }`, "response", "none")
	timeout.TimeoutMS = 50
	started := time.Now()
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), timeout, request, &response); err == nil || time.Since(started) > time.Second {
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
	result, err := first.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "empty" {
		t.Fatalf("first store result=%q err=%v", result.Body, err)
	}
	second := newScriptRuntime(statePath)
	result, err = second.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "1" {
		t.Fatalf("persisted store result=%q err=%v", result.Body, err)
	}
	module.PersistentStorage = false
	if _, err := second.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response); err == nil {
		t.Fatal("storage API was exposed without permission")
	}
}

func TestNativeActionMatchingIsScopedToExtensionCaptureHosts(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	inside := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	outside := scriptMessage{URL: "https://other.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	if len(matchingScriptRules(cfg, "response", inside)) != 1 || len(matchingScriptRules(cfg, "response", outside)) != 0 {
		t.Fatal("native action escaped its extension capture host boundary")
	}
}

func TestNativeActionMatchingUsesTopLevelExecutionOrderForBothPhases(t *testing.T) {
	t.Parallel()
	first := nativeRuntimeModule()
	first.ID = "io.example.first"
	first.Enabled = true
	first.Scripts = []ScriptRule{
		nativeRuntimeRule(`function transform() { return null }`, "request", "none"),
		nativeRuntimeRule(`function transform() { return null }`, "response", "none"),
	}
	first.Scripts[0].ID = "first-request"
	first.Scripts[1].ID = "first-response"
	second := nativeRuntimeModule()
	second.ID = "io.example.second"
	second.Enabled = true
	second.Scripts = []ScriptRule{
		nativeRuntimeRule(`function transform() { return null }`, "request", "none"),
		nativeRuntimeRule(`function transform() { return null }`, "response", "none"),
	}
	second.Scripts[0].ID = "second-request"
	second.Scripts[1].ID = "second-response"
	cfg := Config{
		Modules:        []Module{first, second},
		ExecutionOrder: []string{second.ID, first.ID},
	}
	message := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	for _, phase := range []string{"request", "response"} {
		matched := matchingScriptRules(cfg, phase, message)
		if len(matched) != 2 || matched[0].Module.ID != second.ID || matched[1].Module.ID != first.ID {
			t.Fatalf("%s order = %+v", phase, matched)
		}
	}
}
