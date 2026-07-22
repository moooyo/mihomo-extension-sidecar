package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

func TestNativeScriptTransformsResponseTrailers(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  if (context.response.trailers["Grpc-Status"] !== "0") throw new Error("missing upstream trailer")
  return { response: { trailers: {"Grpc-Status": "7", "Grpc-Message": "blocked"} } }
}`
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodPost, Headers: make(http.Header)}
	response := scriptMessage{
		URL: request.URL, StatusCode: 200, Headers: make(http.Header),
		Trailers: http.Header{"Grpc-Status": {"0"}},
	}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(source, "response", "none"), request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedTrailers || result.Trailers.Get("Grpc-Status") != "7" || result.Trailers.Get("Grpc-Message") != "blocked" {
		t.Fatalf("native trailer result = %+v", result)
	}
}

func TestNativeScriptRejectsRequestAndFramingTrailers(t *testing.T) {
	t.Parallel()
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodPost, Headers: make(http.Header)}
	requestRule := nativeRuntimeRule(`function transform() { return {request: {trailers: {"X-Final": "value"}}} }`, "request", "none")
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), requestRule, request, nil); err == nil {
		t.Fatal("request trailer patch was accepted")
	}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	responseTE := nativeRuntimeRule(`function transform() { return {response: {headers: {"TE": "trailers"}}} }`, "response", "none")
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseTE, request, &response); err == nil {
		t.Fatal("response TE header was accepted")
	}
	for _, name := range []string{"Content-Length", "Content-Type", "Authorization", "If-Match"} {
		name := name
		t.Run(name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {response: {trailers: {%q: "value"}}} }`, name)
			responseRule := nativeRuntimeRule(source, "response", "none")
			if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseRule, request, &response); err == nil {
				t.Fatalf("forbidden trailer %q was accepted", name)
			}
		})
	}
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "NUL", value: "value\x00tail"},
		{name: "DEL", value: "value\x7ftail"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {response: {trailers: {"X-Final": %q}}} }`, test.value)
			responseRule := nativeRuntimeRule(source, "response", "none")
			if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseRule, request, &response); err == nil {
				t.Fatalf("invalid trailer value %q was accepted", test.value)
			}
		})
	}
}

func TestExportedHeadersEnforceDeterministicHardLimits(t *testing.T) {
	t.Parallel()
	tooManyFields := make(map[string]any, maxScriptHeaderFields+1)
	for index := 0; index <= maxScriptHeaderFields; index++ {
		tooManyFields[fmt.Sprintf("X-Field-%03d", index)] = "value"
	}
	tooManyValues := make([]any, maxScriptHeaderValues+1)
	for index := range tooManyValues {
		tooManyValues[index] = ""
	}
	totalOverflow := make(map[string]any)
	for index := 0; index < 5; index++ {
		totalOverflow[fmt.Sprintf("X-Total-%d", index)] = strings.Repeat("x", maxScriptHeaderValueBytes)
	}
	for name, value := range map[string]any{
		"field count":      tooManyFields,
		"value count":      map[string]any{"X-Many": tooManyValues},
		"single value":     map[string]any{"X-Large": strings.Repeat("x", maxScriptHeaderValueBytes+1)},
		"total bytes":      totalOverflow,
		"duplicate casing": map[string]any{"X-Duplicate": "one", "x-duplicate": "two"},
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			var first string
			for attempt := 0; attempt < 8; attempt++ {
				_, err := exportedHeaders(value)
				if err == nil {
					t.Fatal("oversized or ambiguous headers were accepted")
				}
				if attempt == 0 {
					first = err.Error()
				} else if err.Error() != first {
					t.Fatalf("nondeterministic errors: first=%q current=%q", first, err)
				}
			}
		})
	}
	if _, err := exportedTrailers(map[string]any{"Grpc-Status": "0", "grpc-status": "1"}); err == nil {
		t.Fatal("case-insensitive duplicate trailers were accepted")
	}
	headers, err := exportedHeaders(map[string]any{"X-Multi": []string{"one", "two"}})
	if err != nil || len(headers.Values("X-Multi")) != 2 {
		t.Fatalf("[]string headers=%v err=%v", headers, err)
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
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = runtime
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
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = runtime
	message := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	for _, phase := range []string{"request", "response"} {
		matched := matchingScriptRules(cfg, phase, message)
		if len(matched) != 2 || matched[0].Module.ID != second.ID || matched[1].Module.ID != first.ID {
			t.Fatalf("%s order = %+v", phase, matched)
		}
	}
}

var benchmarkMatchedScriptRules []matchedScriptRule

func BenchmarkMatchingScriptRulesCompiledConfig(b *testing.B) {
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = make([]ScriptRule, 256)
	for index := range module.Scripts {
		rule := nativeRuntimeRule(`function transform() { return null }`, "response", "none")
		rule.ID = fmt.Sprintf("action-%03d", index)
		rule.Match.PathRegex = fmt.Sprintf("^/path-%03d$", index)
		module.Scripts[index] = rule
	}
	base := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	compiled, err := compileScriptConfig(base)
	if err != nil {
		b.Fatal(err)
	}
	message := scriptMessage{URL: "https://api.example.com/miss", Method: http.MethodGet, StatusCode: 200}
	for _, test := range []struct {
		name     string
		compiled bool
	}{
		{name: "compiled", compiled: true},
		{name: "fallback-compile", compiled: false},
	} {
		b.Run(test.name, func(b *testing.B) {
			cfg := base
			if test.compiled {
				cfg.runtime = compiled
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkMatchedScriptRules = matchingScriptRules(cfg, "response", message)
			}
		})
	}
}

var benchmarkHostMatched bool

func BenchmarkCompiledCaptureHostMatchers(b *testing.B) {
	activeModule := nativeRuntimeModule()
	activeModule.Enabled = true
	activeModule.CaptureHosts = make([]string, 280)
	for index := range activeModule.CaptureHosts {
		activeModule.CaptureHosts[index] = fmt.Sprintf("*.h%03d.example.com", index)
	}
	activeCfg := Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{activeModule}, ExecutionOrder: []string{activeModule.ID},
	}
	activeRuntime, err := compileScriptConfig(activeCfg)
	if err != nil {
		b.Fatal(err)
	}
	activeCfg.runtime = activeRuntime

	ruleModule := nativeRuntimeModule()
	ruleModule.Enabled = true
	ruleModule.CaptureHosts = []string{"*.example.com"}
	ruleModule.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	ruleModule.Scripts[0].Match.Hosts = make([]string, 259)
	for index := range ruleModule.Scripts[0].Match.Hosts {
		ruleModule.Scripts[0].Match.Hosts[index] = fmt.Sprintf("r%03d.example.com", index)
	}
	ruleCfg := Config{Modules: []Module{ruleModule}, ExecutionOrder: []string{ruleModule.ID}}
	ruleRuntime, err := compileScriptConfig(ruleCfg)
	if err != nil {
		b.Fatal(err)
	}
	ruleCfg.runtime = ruleRuntime
	for _, test := range []struct {
		name string
		run  func()
	}{
		{name: "active-wildcard-last", run: func() {
			benchmarkHostMatched = activeInterceptHost(activeCfg, "api.h279.example.com")
		}},
		{name: "rule-exact-last", run: func() {
			benchmarkMatchedScriptRules = matchingScriptRules(ruleCfg, "response", scriptMessage{
				URL: "https://r258.example.com/", Method: http.MethodGet, StatusCode: 200,
			})
		}},
		{name: "rule-exact-miss", run: func() {
			benchmarkMatchedScriptRules = matchingScriptRules(ruleCfg, "response", scriptMessage{
				URL: "https://other.example.com/", Method: http.MethodGet, StatusCode: 200,
			})
		}},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				test.run()
			}
		})
	}
}
