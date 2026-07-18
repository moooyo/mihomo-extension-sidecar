package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeRule(source string) ScriptRule {
	return ScriptRule{
		ID: "script-001", Phase: "response", Pattern: `^https://api\.example\.com/`,
		ScriptURL: "https://modules.example.test/script.js", ScriptDigest: digestText(source), ScriptBody: source,
		TimeoutMS: 500, MaxBodyBytes: 1 << 20,
	}
}

func TestScriptRuntimeResponseCompatibility(t *testing.T) {
	t.Parallel()
	source := `$response.headers["X-Module"] = "active";
$done({status: 201, headers: $response.headers, body: $response.body.replace("secret", "redacted")});`
	runtime := newScriptRuntime()
	result, err := runtime.execute(
		Module{ID: "mod-1234567890abcdef", Argument: "mode=test"},
		runtimeRule(source),
		scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: http.Header{"X-Request": {"yes"}}},
		&scriptMessage{URL: "https://api.example.com/v1", StatusCode: 200, Headers: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("secret value")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedBody || string(result.Body) != "redacted value" || !result.ChangedStatus || result.StatusCode != 201 {
		t.Fatalf("script result = %+v", result)
	}
	if result.Headers.Get("X-Module") != "active" || result.Headers.Get("Content-Type") != "text/plain" {
		t.Fatalf("script headers = %v", result.Headers)
	}
}

func TestScriptRuntimeRequestStatusCreatesSyntheticResponse(t *testing.T) {
	t.Parallel()
	source := `$done({status: "HTTP/1.1 200 OK", headers: {"Content-Type": "application/json"}, body: "{}"});`
	result, err := newScriptRuntime().execute(
		Module{ID: "mod-1234567890abcdef"}, runtimeRule(source),
		scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Synthetic || result.StatusCode != 200 || string(result.Body) != "{}" {
		t.Fatalf("synthetic result = %+v", result)
	}
}

func TestScriptRuntimeBinaryBodyAndAbort(t *testing.T) {
	t.Parallel()
	runtime := newScriptRuntime()
	rule := runtimeRule(`$done({body: new Uint8Array([$response.body[2], $response.body[1], $response.body[0]])});`)
	rule.BinaryBody = true
	result, err := runtime.execute(
		Module{ID: "mod-1234567890abcdef"},
		rule,
		scriptMessage{},
		&scriptMessage{Body: []byte{1, 2, 3}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedBody || !bytes.Equal(result.Body, []byte{3, 2, 1}) {
		t.Fatalf("binary result = %+v", result)
	}
	aborted, err := runtime.execute(Module{ID: "mod-1234567890abcdef"}, runtimeRule(`$done();`), scriptMessage{}, nil)
	if err != nil || !aborted.Abort {
		t.Fatalf("abort result=%+v err=%v", aborted, err)
	}
}

func TestModuleParametersAndHostMappings(t *testing.T) {
	t.Parallel()
	module := Module{
		ID: "mod-1234567890abcdef", Enabled: true,
		Parameters:   []ModuleParameter{{Key: "mode", Kind: "select", Options: []string{"clean", "full"}, Value: "clean"}},
		HostMappings: []HostMapping{{Pattern: "api.example.com", Target: "origin.example.net"}},
	}
	runtime := newScriptRuntime()
	result, err := runtime.execute(module, runtimeRule(`$done({body: $persistentStore.read("mode")});`), scriptMessage{}, nil)
	if err != nil || string(result.Body) != "clean" {
		t.Fatalf("parameter result=%q err=%v", result.Body, err)
	}
	cfg := Config{Modules: []Module{module}}
	if got := mappedInterceptTarget(cfg, "api.example.com"); got != "origin.example.net" {
		t.Fatalf("mapped target = %q", got)
	}
}

func TestScriptRuntimePersistentStore(t *testing.T) {
	t.Parallel()
	runtime := newScriptRuntime()
	module := Module{ID: "mod-1234567890abcdef"}
	if _, err := runtime.execute(module, runtimeRule(`$persistentStore.write("value", "key"); $done();`), scriptMessage{}, nil); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.execute(module, runtimeRule(`$done({body: $persistentStore.read("key")});`), scriptMessage{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "value" {
		t.Fatalf("persistent value = %q", result.Body)
	}
}

func TestScriptRuntimePersistentStoreSurvivesRestart(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	module := Module{ID: "mod-1234567890abcdef"}
	first := newScriptRuntime(statePath)
	if _, err := first.execute(module, runtimeRule(`$persistentStore.write("durable", "key"); $done();`), scriptMessage{}, nil); err != nil {
		t.Fatal(err)
	}
	second := newScriptRuntime(statePath)
	result, err := second.execute(module, runtimeRule(`$done({body: $persistentStore.read("key")});`), scriptMessage{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "durable" {
		t.Fatalf("reloaded value = %q", result.Body)
	}
	second.prune(nil)
	third := newScriptRuntime(statePath)
	if len(third.persistent) != 0 {
		t.Fatalf("deleted module state was retained: %+v", third.persistent)
	}
}

func TestScriptRuntimeTimeoutAndNetworkDenial(t *testing.T) {
	t.Parallel()
	runtime := newScriptRuntime()
	rule := runtimeRule(`for (;;) {}`)
	rule.TimeoutMS = 50
	started := time.Now()
	if _, err := runtime.execute(Module{ID: "mod-1234567890abcdef"}, rule, scriptMessage{}, nil); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("script timeout did not interrupt promptly")
	}
	if _, err := runtime.execute(Module{ID: "mod-1234567890abcdef"}, runtimeRule(`$httpClient.get("https://example.com/", function() {});`), scriptMessage{}, nil); err == nil || !strings.Contains(err.Error(), "network access is disabled") {
		t.Fatalf("network denial error = %v", err)
	}
}

func TestScriptRuntimeBoundsBacktrackingRegexpFallback(t *testing.T) {
	t.Parallel()
	runtime := newScriptRuntime()
	source := `new RegExp("(?=(a+)+$)").test("a".repeat(50000) + "!"); $done();`
	rule := runtimeRule(source)
	rule.TimeoutMS = 2000
	started := time.Now()
	_, _ = runtime.execute(Module{ID: "mod-1234567890abcdef"}, rule, scriptMessage{}, nil)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("regexp timeout took %s", elapsed)
	}
}

func TestDynamicHostPatternMatching(t *testing.T) {
	t.Parallel()
	cfg := Config{Modules: []Module{{Enabled: true, Hosts: []string{"api.example.com", "*.cdn.example.com"}}}}
	for host, want := range map[string]bool{
		"api.example.com":   true,
		"a.cdn.example.com": true,
		"cdn.example.com":   false,
		"other.example.com": false,
	} {
		if got := activeInterceptHost(cfg, host); got != want {
			t.Errorf("activeInterceptHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestModuleHeaderRewriteAppliesBeforeUpstream(t *testing.T) {
	t.Parallel()
	cfg := Config{Modules: []Module{{
		ID: "mod-1234567890abcdef", Enabled: true, Hosts: []string{"api.example.com"},
		Headers: []HeaderRule{{ID: "header-001", Pattern: `^https://api\.example\.com/`, Operation: "delete", Header: "Cookie"}, {
			ID: "header-002", Pattern: `^https://api\.example\.com/`, Operation: "replace", Header: "User-Agent", Value: "5gpn-test",
		}},
	}}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	request.Header.Set("Cookie", "secret=1")
	request.Header.Set("User-Agent", "original")
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), request, cfg, "api.example.com")
	if err != nil || handled {
		t.Fatalf("prepare request handled=%v err=%v", handled, err)
	}
	if outbound.Header.Get("Cookie") != "" || outbound.Header.Get("User-Agent") != "5gpn-test" {
		t.Fatalf("rewritten headers = %v", outbound.Header)
	}
}

func TestPlainHTTPRequestKeepsHTTPUpstreamScheme(t *testing.T) {
	t.Parallel()
	cfg := Config{Modules: []Module{{ID: "mod-1234567890abcdef", Enabled: true, Hosts: []string{"api.example.com"}}}}
	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/path", nil)
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), request, cfg, "api.example.com")
	if err != nil || handled {
		t.Fatalf("prepare request handled=%v err=%v", handled, err)
	}
	if outbound.URL.Scheme != "http" || outbound.URL.Hostname() != "api.example.com" {
		t.Fatalf("plain HTTP outbound URL = %s", outbound.URL)
	}
	if !allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 80}) ||
		!allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 443}) ||
		allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 8080}) {
		t.Fatal("SOCKS target port boundary is not limited to HTTP/HTTPS")
	}
}

func TestBodyBufferAdmissionFailsClosed(t *testing.T) {
	t.Parallel()
	proxy := &interceptProxy{bodySlots: make(chan struct{}, 2)}
	if !proxy.acquireBodySlot() || !proxy.acquireBodySlot() || proxy.acquireBodySlot() {
		t.Fatal("body-buffer admission did not enforce its fixed capacity")
	}
	proxy.releaseBodySlot()
	if !proxy.acquireBodySlot() {
		t.Fatal("body-buffer capacity was not released")
	}
}
