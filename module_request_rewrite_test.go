package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizeModuleRequestURLRewrite(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.CaptureHosts = []string{"api.example.com", "other.example.com"}
	module.NetworkOrigins = []string{
		"http://upgrade.example.com",
		"https://worker.example.com",
		"https://worker.example.com:8443",
	}

	tests := []struct {
		name       string
		currentURL string
		targetURL  string
		wantURL    string
		wantError  string
	}{
		{
			name: "same origin", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://api.example.com/v1/next?video=1", wantURL: "https://api.example.com/v1/next?video=1",
		},
		{
			name: "same origin retains host representation", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://API.EXAMPLE.COM:443/v1/next", wantURL: "https://API.EXAMPLE.COM:443/v1/next",
		},
		{
			name: "declared cross origin", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com/?target=https%3A%2F%2Fapi.example.com%2Fv1%2Fplayer", wantURL: "https://worker.example.com/?target=https%3A%2F%2Fapi.example.com%2Fv1%2Fplayer",
		},
		{
			name: "declared custom port", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com:8443/process", wantURL: "https://worker.example.com:8443/process",
		},
		{
			name: "protocol upgrade", currentURL: "http://api.example.com/v1/player",
			targetURL: "https://worker.example.com/process", wantURL: "https://worker.example.com/process",
		},
		{
			name: "undeclared origin", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://undeclared.example.com/process", wantError: "is not declared",
		},
		{
			name: "declared host with wrong scheme", currentURL: "http://api.example.com/v1/player",
			targetURL: "http://worker.example.com/process", wantError: "is not declared",
		},
		{
			name: "declared host with wrong port", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com:9443/process", wantError: "is not declared",
		},
		{
			name: "other capture host still requires origin permission", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://other.example.com/process", wantError: "is not declared",
		},
		{
			name: "protocol downgrade", currentURL: "https://api.example.com/v1/player",
			targetURL: "http://upgrade.example.com/process", wantError: "cannot downgrade",
		},
		{
			name: "userinfo", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://user:secret@worker.example.com/process", wantError: "without credentials",
		},
		{
			name: "fragment", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com/process#fragment", wantError: "without credentials or a fragment",
		},
		{
			name: "empty fragment", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com/process#", wantError: "without credentials or a fragment",
		},
		{
			name: "relative URL", currentURL: "https://api.example.com/v1/player",
			targetURL: "/process", wantError: "absolute HTTP URL",
		},
		{
			name: "empty URL", currentURL: "https://api.example.com/v1/player",
			targetURL: "", wantError: "1 to 16384 bytes",
		},
		{
			name: "oversized URL", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com/" + strings.Repeat("x", maxModuleRequestRewriteURLBytes), wantError: "1 to 16384 bytes",
		},
		{
			name: "IP origin", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://192.0.2.1/process", wantError: "host is unsafe",
		},
		{
			name: "noncanonical host case", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://WORKER.EXAMPLE.COM/process", wantError: "must be canonical",
		},
		{
			name: "noncanonical default port", currentURL: "https://api.example.com/v1/player",
			targetURL: "https://worker.example.com:443/process", wantError: "must be canonical",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := authorizeModuleRequestURLRewrite(module, test.currentURL, test.targetURL)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want substring %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if parsed.String() != test.wantURL {
				t.Fatalf("URL = %q, want %q", parsed.String(), test.wantURL)
			}
		})
	}
}

func TestParseModuleNetworkRequestURLRejectsEmptyFragment(t *testing.T) {
	t.Parallel()
	if _, _, _, err := parseModuleNetworkRequestURL("https://worker.example.com/path#"); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("empty fragment error = %v", err)
	}
}

func TestCrossOriginRequestRewritePreservesRequestAndUsesAuthenticatedSOCKS(t *testing.T) {
	t.Parallel()
	type observedRequest struct {
		method        string
		host          string
		body          string
		cookie        string
		authorization string
		endToEnd      string
		connection    string
		contentCoding string
	}
	observed := make(chan observedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- observedRequest{
			method: request.Method, host: request.Host, body: string(body),
			cookie: request.Header.Get("Cookie"), authorization: request.Header.Get("Authorization"),
			endToEnd: request.Header.Get("X-End-To-End"), connection: request.Header.Get("Connection"),
			contentCoding: request.Header.Get("Content-Encoding"),
		}
		_, _ = w.Write([]byte("worker-response"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyConfig, targets := startTestSOCKSTCPRelay(t, upstreamURL.Host)

	source := `function transform(context) {
  return {request: {url: "http://worker.example.com/process?target=" + encodeURIComponent(context.request.url)}}
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.NetworkOrigins = []string{"http://worker.example.com"}
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "binary")}
	module.Scripts[0].Match.Schemes = []string{"http"}
	cfg := Config{
		MITM: MITMSettings{Enabled: true}, UpstreamProxy: proxyConfig,
		Modules: []Module{module}, ExecutionOrder: []string{module.ID},
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("decoded-binary-body")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/initplayback?oad=1", bytes.NewReader(compressed.Bytes()))
	incoming.Header.Set("Content-Encoding", "gzip")
	incoming.Header.Set("Cookie", "session=secret")
	incoming.Header.Set("Authorization", "Bearer credential")
	incoming.Header.Set("X-End-To-End", "preserved")
	incoming.Header.Set("Connection", "X-Hop")
	incoming.Header.Set("X-Hop", "removed")

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, cfg, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if outbound.Method != http.MethodPost || outbound.URL.String() != "http://worker.example.com/process?target=http%3A%2F%2Fapi.example.com%2Finitplayback%3Foad%3D1" {
		t.Fatalf("outbound method=%s URL=%s", outbound.Method, outbound.URL)
	}
	response, cleanup, err := proxy.roundTrip(outbound, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "worker-response" {
		t.Fatalf("worker response body=%q err=%v", body, err)
	}

	select {
	case target := <-targets:
		if target != (socksTarget{Host: "worker.example.com", Port: 80}) {
			t.Fatalf("SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated SOCKS target was not observed")
	}
	select {
	case request := <-observed:
		if request.method != http.MethodPost || request.host != "worker.example.com" || request.body != "decoded-binary-body" {
			t.Fatalf("worker request = %+v", request)
		}
		if request.cookie != "session=secret" || request.authorization != "Bearer credential" || request.endToEnd != "preserved" {
			t.Fatalf("end-to-end headers were not preserved: %+v", request)
		}
		if request.connection != "" {
			t.Fatalf("hop-by-hop header reached worker: %+v", request)
		}
		if request.contentCoding != "" {
			t.Fatalf("decoded request retained Content-Encoding: %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("worker request was not observed")
	}
}

func TestCrossOriginRequestRewriteDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path == "/first" {
			w.Header().Set("Location", "http://worker.example.com/second")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("followed"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyConfig, targets := startTestSOCKSTCPRelay(t, upstreamURL.Host)

	module := nativeRuntimeModule()
	module.Enabled = true
	module.NetworkOrigins = []string{"http://worker.example.com"}
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {url: "http://worker.example.com/first"}} }`,
		"request",
		"none",
	)}
	module.Scripts[0].Match.Schemes = []string{"http"}
	cfg := Config{
		MITM: MITMSettings{Enabled: true}, UpstreamProxy: proxyConfig,
		Modules: []Module{module}, ExecutionOrder: []string{module.ID},
	}
	incoming := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1", nil)
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, cfg, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	response, cleanup, err := proxy.roundTrip(outbound, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "http://worker.example.com/second" {
		t.Fatalf("status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	if calls.Load() != 1 {
		t.Fatalf("redirect was followed; upstream calls=%d", calls.Load())
	}
	select {
	case target := <-targets:
		if target != (socksTarget{Host: "worker.example.com", Port: 80}) {
			t.Fatalf("SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated SOCKS target was not observed")
	}
}

func TestPrepareModuleRequestFailsClosedOnUndeclaredCrossOriginRewrite(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {url: "https://worker.example.com/process"}} }`,
		"request",
		"none",
	)}
	cfg := Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err == nil || !strings.Contains(err.Error(), "origin \"https://worker.example.com\" is not declared") {
		t.Fatalf("outbound=%v handled=%v err=%v", outbound, handled, err)
	}
}

func TestPrepareModuleRequestUsesCanonicalCrossOriginAuthority(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.NetworkOrigins = []string{"https://worker.example.com:8443"}
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {url: "https://worker.example.com:8443/process"}} }`,
		"request",
		"none",
	)}
	cfg := Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if outbound.URL.String() != "https://worker.example.com:8443/process" || outbound.Host != "worker.example.com:8443" {
		t.Fatalf("URL=%q authority=%q", outbound.URL, outbound.Host)
	}
}

func TestRequestActionsMayContinueInsideTheirDeclaredRewrittenOrigin(t *testing.T) {
	t.Parallel()
	first := nativeRuntimeRule(
		`function transform() { return {request: {url: "https://worker.example.com/first"}} }`,
		"request",
		"none",
	)
	first.ID = "rewrite-origin"
	second := nativeRuntimeRule(
		`function transform(context) {
  if (context.request.url !== "https://worker.example.com/first") throw new Error("first rewrite was not visible")
  return {request: {url: "https://worker.example.com/second"}}
}`,
		"request",
		"none",
	)
	second.ID = "rewrite-path"
	module := nativeRuntimeModule()
	module.Enabled = true
	module.NetworkOrigins = []string{"https://worker.example.com"}
	module.Scripts = []ScriptRule{first, second}
	cfg := Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if outbound.URL.String() != "https://worker.example.com/second" {
		t.Fatalf("chained URL = %q", outbound.URL)
	}
}

func TestOverlappingRequestActionRequiresItsOwnRewrittenOriginPermission(t *testing.T) {
	t.Parallel()
	first := nativeRuntimeModule()
	first.ID = "io.example.first"
	first.Enabled = true
	first.NetworkOrigins = []string{"https://worker.example.com"}
	first.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {url: "https://worker.example.com/process"}} }`,
		"request",
		"none",
	)}
	second := nativeRuntimeModule()
	second.ID = "io.example.second"
	second.Enabled = true
	second.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform(context) {
  const headers = {...context.request.headers, "X-Second": "ran"}
  return {request: {headers}}
}`,
		"request",
		"none",
	)}
	cfg := Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{first, second},
		ExecutionOrder: []string{first.ID, second.ID},
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err == nil || !strings.Contains(err.Error(), "extension io.example.second request action") ||
		!strings.Contains(err.Error(), "origin \"https://worker.example.com\"") {
		t.Fatalf("outbound=%v handled=%v err=%v", outbound, handled, err)
	}

	second.NetworkOrigins = []string{"https://worker.example.com"}
	cfg.Modules = []Module{first, second}
	request = httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err = (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err != nil || handled {
		t.Fatalf("authorized composition handled=%v err=%v", handled, err)
	}
	if outbound.URL.String() != "https://worker.example.com/process" || outbound.Header.Get("X-Second") != "ran" {
		t.Fatalf("authorized composition URL=%q headers=%v", outbound.URL, outbound.Header)
	}
}

func TestActiveModuleUpstreamTargetRequiresEnabledReviewedOrigin(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.NetworkOrigins = []string{"https://worker.example.com:8443"}
	cfg := Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}}
	if _, allowed := activeModuleUpstreamTarget(cfg, "worker.example.com", "8443"); allowed {
		t.Fatal("disabled module origin was active")
	}
	module.Enabled = true
	cfg.Modules = []Module{module}
	target, allowed := activeModuleUpstreamTarget(cfg, "worker.example.com", "8443")
	if !allowed || target != (socksTarget{Host: "worker.example.com", Port: 8443}) {
		t.Fatalf("active target=%+v allowed=%v", target, allowed)
	}
	cfg.MITM.Enabled = false
	if _, allowed := activeModuleUpstreamTarget(cfg, "worker.example.com", "8443"); allowed {
		t.Fatal("origin stayed active with MITM disabled")
	}
	if _, allowed := activeModuleUpstreamTarget(Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}}, "other.example.com", "8443"); allowed {
		t.Fatal("undeclared origin target was active")
	}
	module.NetworkOrigins = []string{"HTTPS://WORKER.EXAMPLE.COM:443/"}
	if _, allowed := activeModuleUpstreamTarget(Config{MITM: MITMSettings{Enabled: true}, Modules: []Module{module}}, "worker.example.com", "443"); allowed {
		t.Fatal("noncanonical stored origin target was active")
	}
}
