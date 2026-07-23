package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type trackingReadCloser struct {
	reader *bytes.Reader
	reads  int
	closes int
	onEOF  func()
}

func (r *trackingReadCloser) Read(buffer []byte) (int, error) {
	r.reads++
	read, err := r.reader.Read(buffer)
	if err == io.EOF && r.onEOF != nil {
		r.onEOF()
		r.onEOF = nil
	}
	return read, err
}

func (r *trackingReadCloser) Close() error {
	r.closes++
	return nil
}

func TestPrepareModuleRequestNormalizesTETrailers(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "https://api.example.com/grpc", nil)
	request.Header.Set("TE", " Trailers ")
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, Config{}, "api.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if handled || outbound.Header.Get("Te") != "trailers" || len(outbound.Header.Values("Te")) != 1 {
		t.Fatalf("handled=%v headers=%v", handled, outbound.Header)
	}

	invalid := httptest.NewRequest(http.MethodPost, "https://api.example.com/grpc", nil)
	invalid.Header.Set("TE", "gzip")
	invalidOutbound, invalidHandled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), invalid, Config{}, "api.example.com",
	)
	if err != nil || invalidHandled || invalidOutbound.Header.Get("Te") != "" {
		t.Fatalf("raw invalid TE was not stripped: handled=%v headers=%v err=%v", invalidHandled, invalidOutbound.Header, err)
	}

	connectionScoped := httptest.NewRequest(http.MethodPost, "https://api.example.com/grpc", nil)
	connectionScoped.Header.Set("TE", "trailers")
	connectionScoped.Header.Set("Connection", "TE")
	outbound, _, err = (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), connectionScoped, Config{}, "api.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Header.Get("Te") != "trailers" || outbound.Header.Get("Connection") != "" {
		t.Fatalf("compliant HTTP/1 TE was not re-established: %v", outbound.Header)
	}
}

func TestNativeRequestPatchRejectsHopByHopHeaders(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {headers: {"Connection": "close"}}} }`,
		"request", "none",
	)}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	if _, _, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	); err == nil {
		t.Fatal("native request patch injected a hop-by-hop header")
	}
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {headers: {"TE": "gzip"}}} }`,
		"request", "none",
	)}
	cfg.Modules = []Module{module}
	if _, _, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	); err == nil {
		t.Fatal("native request patch injected an invalid TE value")
	}
}

func TestNativeRequestPatchAllowsOnlyTETrailers(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {request: {headers: {"TE": "Trailers", "X-Native": "yes"}}} }`,
		"request", "none",
	)}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), request, cfg, "api.example.com",
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if outbound.Header.Get("Te") != "trailers" || outbound.Header.Get("X-Native") != "yes" {
		t.Fatalf("headers=%v", outbound.Header)
	}
}

func TestForwardedTETrailersReachesHTTP2GRPCUpstream(t *testing.T) {
	t.Parallel()
	observed := make(chan *http.Request, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.ReadAll(request.Body)
		observed <- request.Clone(request.Context())
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write([]byte("grpc"))
		w.Header().Set("Grpc-Status", "0")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	body := &trackingReadCloser{reader: bytes.NewReader([]byte("grpc-request"))}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/grpc", nil)
	incoming.Body = body
	incoming.ContentLength = int64(body.reader.Len())
	incoming.Header.Set("Content-Type", "application/grpc")
	incoming.Header.Set("TE", "Trailers")
	incoming.Trailer = http.Header{"Grpc-Timeout": nil}
	body.onEOF = func() { incoming.Trailer.Set("Grpc-Timeout", "1S") }
	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), incoming, Config{}, "api.example.com",
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	upstreamURL, err := url.Parse(upstream.URL + "/grpc")
	if err != nil {
		t.Fatal(err)
	}
	outbound.URL = upstreamURL
	response, err := upstream.Client().Do(outbound)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	request := <-observed
	if request.ProtoMajor != 2 || request.Header.Get("Te") != "trailers" || request.Trailer.Get("Grpc-Timeout") != "1S" {
		t.Fatalf("protocol=%s headers=%v trailers=%v", request.Proto, request.Header, request.Trailer)
	}
	if response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("trailers=%v", response.Trailer)
	}
}

func TestMainHTTPTransportBoundsResponseHeaders(t *testing.T) {
	t.Parallel()
	transport := (&interceptProxy{}).newHTTPTransport(Config{})
	defer transport.CloseIdleConnections()
	if transport.MaxResponseHeaderBytes != maxModuleNetworkHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes = %d", transport.MaxResponseHeaderBytes)
	}
	if transport.MaxIdleConns != maxIdleUpstreamHTTPConnections ||
		transport.MaxIdleConnsPerHost != maxIdleUpstreamHTTPConnectionsPerHost ||
		transport.IdleConnTimeout != upstreamHTTPIdleTimeout {
		t.Fatalf("idle pool is not bounded: %+v", transport)
	}
}

func TestPrepareModuleRequestStreamsUnmatchedHTTPBody(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("encoded-body"))}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
	incoming.Body = body
	incoming.ContentLength = int64(body.reader.Len())
	incoming.Header.Set("Content-Encoding", "gzip")
	incoming.Header.Set("Te", "trailers")
	incoming.Trailer = http.Header{"Grpc-Status": nil}
	body.onEOF = func() { incoming.Trailer.Set("Grpc-Status", "0") }

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if body.reads != 0 {
		t.Fatalf("unmatched body was consumed during preparation: reads=%d", body.reads)
	}
	if outbound.Header.Get("Content-Encoding") != "gzip" || outbound.ContentLength != int64(len("encoded-body")) {
		t.Fatalf("streaming request lost framing metadata: headers=%v length=%d", outbound.Header, outbound.ContentLength)
	}
	if requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("unmatched HTTP/1 request unexpectedly requires a body slot")
	}
	streamed, err := io.ReadAll(outbound.Body)
	if err != nil || string(streamed) != "encoded-body" {
		t.Fatalf("streamed body=%q err=%v", streamed, err)
	}
	if outbound.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("streaming request lost late trailers: %v", outbound.Trailer)
	}
}

func TestUnmatchedKnownLengthRequestStreamsRawEncodingOverWireAndRunsResponseAction(t *testing.T) {
	t.Parallel()
	var encoded bytes.Buffer
	encoder := gzip.NewWriter(&encoded)
	if _, err := encoder.Write([]byte("decoded-payload")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	rawBody := append([]byte(nil), encoded.Bytes()...)
	type observedRequest struct {
		body            []byte
		contentEncoding string
		acceptEncoding  string
		contentLength   int64
	}
	observed := make(chan observedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		observed <- observedRequest{
			body:            body,
			contentEncoding: request.Header.Get("Content-Encoding"),
			acceptEncoding:  request.Header.Get("Accept-Encoding"),
			contentLength:   request.ContentLength,
		}
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := socksTarget{Host: "api.example.com", Port: 80}
	proxyConfig, targets, _ := startTestSOCKSTCPRouter(t, map[string]string{
		testSOCKSTargetKey(target): upstreamURL.Host,
	})

	source := `function transform(context) { return {response: {body: context.response.body + "-patched"}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "response", "text")}
	module.Scripts[0].Match.Schemes = []string{"http"}
	cfg := Config{
		MITM:           MITMSettings{Enabled: true},
		UpstreamProxy:  proxyConfig,
		Modules:        []Module{module},
		ExecutionOrder: []string{module.ID},
	}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", bytes.NewReader(rawBody))
	incoming.Header.Set("Content-Encoding", "gzip")
	incoming.Header.Set("Accept-Encoding", "br")
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, cfg, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	response, cleanup, err := proxy.roundTrip(outbound, cfg)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal(err)
	}
	defer response.Body.Close()
	defer cleanup()
	responseRules := matchingScriptRules(cfg, "response", scriptMessage{
		URL: outbound.URL.String(), Method: outbound.Method, StatusCode: response.StatusCode,
	})
	transformed, err := proxy.transformModuleResponse(outbound, response, cfg, responseRules)
	if err != nil {
		t.Fatal(err)
	}
	if transformed == nil || string(transformed.Body) != "upstream-patched" {
		t.Fatalf("transformed response = %+v", transformed)
	}
	waitForSOCKSTarget(t, targets, target)
	select {
	case got := <-observed:
		if !bytes.Equal(got.body, rawBody) || got.contentEncoding != "gzip" || got.acceptEncoding != "identity" || got.contentLength != int64(len(rawBody)) {
			t.Fatalf("upstream request = body_equal:%t content_encoding:%q accept_encoding:%q content_length:%d", bytes.Equal(got.body, rawBody), got.contentEncoding, got.acceptEncoding, got.contentLength)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not observed")
	}
}

func TestPrepareModuleRequestBuffersUnmatchedHTTP3BodyForReplay(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
	incoming.Proto = "HTTP/3.0"
	incoming.ProtoMajor = 3
	incoming.ProtoMinor = 0
	incoming.Body = body
	incoming.ContentLength = int64(body.reader.Len())

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if body.reads == 0 || outbound.Body == body || outbound.GetBody == nil {
		t.Fatalf("HTTP/3 body is not replayable: reads=%d body=%T getBody=%v", body.reads, outbound.Body, outbound.GetBody != nil)
	}
	if !requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("HTTP/3 payload did not reserve a body slot")
	}
}

func TestPrepareModuleRequestKeepsEmptyHTTP3BodyForTrailerReplay(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader(nil)}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/trailer-only", nil)
	incoming.Proto = "HTTP/3.0"
	incoming.ProtoMajor = 3
	incoming.ProtoMinor = 0
	incoming.Body = body
	incoming.ContentLength = 0
	incoming.Trailer = http.Header{"Grpc-Status": nil}
	body.onEOF = func() { incoming.Trailer.Set("Grpc-Status", "0") }
	probe := moduleRequestProbe(incoming, "api.example.com")
	if !requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("HTTP/3 trailer-only request did not reserve body capacity")
	}

	outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
		httptest.NewRecorder(), incoming, Config{}, probe, nil,
	)
	if err != nil || handled || !retained || body.reads == 0 || body.closes == 0 || outbound.Body == nil || outbound.GetBody == nil {
		t.Fatalf("handled=%v retained=%v reads=%d closes=%d body=%T get_body=%v err=%v", handled, retained, body.reads, body.closes, outbound.Body, outbound.GetBody != nil, err)
	}
	if outbound.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("prepared trailers=%v", outbound.Trailer)
	}
	if err := resetHTTP3RequestBodyForReplay(outbound); err != nil {
		t.Fatal(err)
	}
	if outbound.Body == nil || !requestHasBodySection(outbound) {
		t.Fatalf("replayed body=%T trailers=%v", outbound.Body, outbound.Trailer)
	}
	replayed, err := io.ReadAll(outbound.Body)
	if err != nil || len(replayed) != 0 || outbound.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("replayed body=%q trailers=%v err=%v", replayed, outbound.Trailer, err)
	}
}

func TestPrepareModuleRequestAllowsFirstBodylessHTTP3VersionReplay(t *testing.T) {
	incoming := httptest.NewRequest(http.MethodGet, "https://api.example.com/bodyless", nil)
	incoming.Proto = "HTTP/3.0"
	incoming.ProtoMajor = 3
	incoming.ProtoMinor = 0
	probe := moduleRequestProbe(incoming, "api.example.com")
	if requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("bodyless HTTP/3 request unexpectedly reserved body capacity")
	}

	outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
		httptest.NewRecorder(), incoming, Config{}, probe, nil,
	)
	if err != nil || handled || retained {
		t.Fatalf("handled=%v retained=%v err=%v", handled, retained, err)
	}
	if err := resetHTTP3RequestBodyForReplay(outbound); err != nil {
		t.Fatal(err)
	}
	if outbound.Body != nil {
		t.Fatalf("bodyless replay retained body %T", outbound.Body)
	}
}

func TestPrepareModuleRequestBuffersUnknownLengthUnmatchedBody(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
	incoming.Body = body
	incoming.ContentLength = -1
	incoming.TransferEncoding = []string{"chunked"}

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if body.reads == 0 || outbound.Body == body || outbound.GetBody == nil {
		t.Fatalf("unknown body bypassed buffering: reads=%d body=%T getBody=%v", body.reads, outbound.Body, outbound.GetBody != nil)
	}
	if !requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("unknown-length body did not reserve a body slot")
	}
}

func TestPrepareModuleRequestRejectsKnownOversizeBeforeRead(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("not-read"))}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
	incoming.Body = body
	incoming.ContentLength = maxModuleHTTPBody + 1

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err == nil || handled || outbound != nil {
		t.Fatalf("oversize request was accepted: outbound=%v handled=%v err=%v", outbound, handled, err)
	}
	if body.reads != 0 {
		t.Fatalf("known oversize request body was read %d times", body.reads)
	}
	if requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("known oversize request reserved a body slot before rejection")
	}
}

func TestServeHTTPRejectsKnownOversizeBeforeSOCKSDial(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:17890")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
			accepted <- struct{}{}
		}
	}()
	cfg := validNativeConfig()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &interceptProxy{
		config: store, scripts: newScriptRuntime(), bodySlots: make(chan struct{}, 2),
	}
	requestBody := &trackingReadCloser{reader: bytes.NewReader([]byte("must-not-be-read"))}
	request := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
	request.Body = requestBody
	request.ContentLength = maxModuleHTTPBody + 1
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("oversize response status = %d", recorder.Code)
	}
	if requestBody.reads != 0 {
		t.Fatalf("oversize request body was read %d times", requestBody.reads)
	}
	select {
	case <-accepted:
		t.Fatal("known oversize request reached the upstream SOCKS listener")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPrepareModuleRequestStreamsAllNoneIdentityBody(t *testing.T) {
	source := `function transform(context) {
  if ("body" in context.request) throw new Error("none action received a body")
  return {request: {headers: {...context.request.headers, "X-Action": "ran"}}}
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
	incoming.Proto = "HTTP/2.0"
	incoming.ProtoMajor = 2
	incoming.ProtoMinor = 0
	incoming.Body = body
	incoming.ContentLength = int64(body.reader.Len())
	incoming.Header.Set("Content-Encoding", " Identity ")
	incoming.Trailer = http.Header{"Grpc-Status": nil}
	body.onEOF = func() { incoming.Trailer.Set("Grpc-Status", "0") }
	probe := moduleRequestProbe(incoming, "api.example.com")
	rules := matchingScriptRules(cfg, "request", probe)
	if !requestNeedsModuleBodyReservation(incoming, rules) {
		t.Fatal("conditional stream did not reserve a body slot before action execution")
	}

	outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
		httptest.NewRecorder(), incoming, cfg, probe, rules,
	)
	if err != nil || handled || retained {
		t.Fatalf("handled=%v retained=%v err=%v", handled, retained, err)
	}
	if body.reads != 0 {
		t.Fatalf("none action consumed the request body during preparation: reads=%d", body.reads)
	}
	if outbound.Header.Get("X-Action") != "ran" || outbound.Header.Get("Content-Encoding") != "" || outbound.ContentLength != int64(len("payload")) {
		t.Fatalf("outbound headers=%v content_length=%d", outbound.Header, outbound.ContentLength)
	}
	streamed, err := io.ReadAll(outbound.Body)
	if err != nil || string(streamed) != "payload" {
		t.Fatalf("streamed body=%q err=%v", streamed, err)
	}
	if outbound.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("late trailer=%v", outbound.Trailer)
	}
}

func TestBodylessRequestActionReservesSlotUntilItsResultIsKnown(t *testing.T) {
	tests := []struct {
		name         string
		source       string
		wantRetained bool
		wantBody     string
	}{
		{name: "no body result", source: `function transform() {}`},
		{name: "replacement body", source: `function transform() { return {request: {body: "created"}} }`, wantRetained: true, wantBody: "created"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := nativeRuntimeModule()
			module.Enabled = true
			module.Scripts = []ScriptRule{nativeRuntimeRule(test.source, "request", "none")}
			cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
			incoming := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
			probe := moduleRequestProbe(incoming, "api.example.com")
			rules := matchingScriptRules(cfg, "request", probe)
			if !requestNeedsModuleBodyReservation(incoming, rules) {
				t.Fatal("bodyless action did not reserve a slot before execution")
			}

			outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
				httptest.NewRecorder(), incoming, cfg, probe, rules,
			)
			if err != nil || handled || retained != test.wantRetained {
				t.Fatalf("handled=%v retained=%v want_retained=%v err=%v", handled, retained, test.wantRetained, err)
			}
			var body []byte
			if outbound.Body != nil {
				body, err = io.ReadAll(outbound.Body)
			}
			if err != nil || string(body) != test.wantBody || (!test.wantRetained && outbound.Body != nil) {
				t.Fatalf("body=%q want=%q outbound_body=%T err=%v", body, test.wantBody, outbound.Body, err)
			}
		})
	}
}

func TestServeHTTPFullBodySlotsRejectBodylessActionBeforeStorageSideEffect(t *testing.T) {
	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, "store.json")
	source := `function transform(context) {
  if (!context.storage.set("executed", "yes")) throw new Error("storage write failed")
  return {response: {status: 200, body: "executed"}}
}`
	cfg := validNativeConfig()
	cfg.Modules[0].PersistentStorage = true
	cfg.Modules[0].Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "none")}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "config.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &interceptProxy{
		config: store, scripts: newScriptRuntime(statePath), bodySlots: make(chan struct{}, 2),
	}
	proxy.bodySlots <- struct{}{}
	proxy.bodySlots <- struct{}{}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "body capacity is busy") {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bodyless action produced a storage side effect: err=%v", err)
	}
}

func TestPrepareModuleRequestAllNoneEncodedAndHTTP3BodiesRemainBuffered(t *testing.T) {
	source := `function transform(context) {
  if ("body" in context.request) throw new Error("none action received a body")
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}

	t.Run("gzip", func(t *testing.T) {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		_, _ = writer.Write([]byte("decoded"))
		_ = writer.Close()
		body := &trackingReadCloser{reader: bytes.NewReader(encoded.Bytes())}
		incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
		incoming.Body = body
		incoming.ContentLength = int64(body.reader.Len())
		incoming.Header.Set("Content-Encoding", "gzip")
		probe := moduleRequestProbe(incoming, "api.example.com")
		rules := matchingScriptRules(cfg, "request", probe)

		outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
			httptest.NewRecorder(), incoming, cfg, probe, rules,
		)
		if err != nil || handled || !retained {
			t.Fatalf("handled=%v retained=%v err=%v", handled, retained, err)
		}
		decoded, err := io.ReadAll(outbound.Body)
		if err != nil || string(decoded) != "decoded" || body.reads == 0 || outbound.GetBody == nil || outbound.Header.Get("Content-Encoding") != "" {
			t.Fatalf("body=%q reads=%d get_body=%v headers=%v err=%v", decoded, body.reads, outbound.GetBody != nil, outbound.Header, err)
		}
	})

	t.Run("http3", func(t *testing.T) {
		body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
		incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
		incoming.Proto = "HTTP/3.0"
		incoming.ProtoMajor = 3
		incoming.ProtoMinor = 0
		incoming.Body = body
		incoming.ContentLength = int64(body.reader.Len())
		probe := moduleRequestProbe(incoming, "api.example.com")
		rules := matchingScriptRules(cfg, "request", probe)

		outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
			httptest.NewRecorder(), incoming, cfg, probe, rules,
		)
		if err != nil || handled || !retained || body.reads == 0 || outbound.GetBody == nil {
			t.Fatalf("handled=%v retained=%v reads=%d get_body=%v err=%v", handled, retained, body.reads, outbound.GetBody != nil, err)
		}
	})

	t.Run("multiple content encodings", func(t *testing.T) {
		body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
		incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
		incoming.Body = body
		incoming.ContentLength = int64(body.reader.Len())
		incoming.Header["Content-Encoding"] = []string{"identity", "gzip"}
		probe := moduleRequestProbe(incoming, "api.example.com")
		rules := matchingScriptRules(cfg, "request", probe)

		_, _, _, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
			httptest.NewRecorder(), incoming, cfg, probe, rules,
		)
		if err == nil || !strings.Contains(err.Error(), "exactly one value") || body.reads != 0 {
			t.Fatalf("reads=%d err=%v", body.reads, err)
		}
	})
}

func TestPrepareModuleRequestPreservesMixedActionOrderAndBodyVisibility(t *testing.T) {
	tests := []struct {
		name     string
		rules    []ScriptRule
		wantBody string
		wantStep string
	}{
		{
			name: "none then text",
			rules: []ScriptRule{
				nativeRuntimeRule(`function transform(context) {
  if ("body" in context.request) throw new Error("none action received a body")
  return {request: {headers: {...context.request.headers, "X-Step": "one"}}}
}`, "request", "none"),
				nativeRuntimeRule(`function transform(context) {
  if (context.request.body !== "payload" || context.request.headers["X-Step"] !== "one") throw new Error("ordered state missing")
  return {request: {body: context.request.body + "-two"}}
}`, "request", "text"),
			},
			wantBody: "payload-two",
			wantStep: "one",
		},
		{
			name: "text then none",
			rules: []ScriptRule{
				nativeRuntimeRule(`function transform(context) {
  return {request: {headers: {...context.request.headers, "X-Step": "one"}, body: context.request.body + "-one"}}
}`, "request", "text"),
				nativeRuntimeRule(`function transform(context) {
  if ("body" in context.request || context.request.headers["X-Step"] !== "one") throw new Error("none projection or order is wrong")
  return {request: {headers: {...context.request.headers, "X-Step": "two"}}}
}`, "request", "none"),
			},
			wantBody: "payload-one",
			wantStep: "two",
		},
		{
			name: "none then binary",
			rules: []ScriptRule{
				nativeRuntimeRule(`function transform(context) {
  return {request: {headers: {...context.request.headers, "X-Step": "one"}}}
}`, "request", "none"),
				nativeRuntimeRule(`function transform(context) {
  if (!(context.request.body instanceof Uint8Array) || context.request.body[0] !== 112 || context.request.headers["X-Step"] !== "one") throw new Error("binary ordered state missing")
  return {request: {body: new Uint8Array([100, 111, 110, 101])}}
}`, "request", "binary"),
			},
			wantBody: "done",
			wantStep: "one",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := nativeRuntimeModule()
			module.Enabled = true
			module.Scripts = test.rules
			for index := range module.Scripts {
				module.Scripts[index].ID = fmt.Sprintf("action-%d", index)
			}
			cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
			body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
			incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
			incoming.Body = body
			incoming.ContentLength = int64(body.reader.Len())
			probe := moduleRequestProbe(incoming, "api.example.com")
			rules := matchingScriptRules(cfg, "request", probe)

			outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
				httptest.NewRecorder(), incoming, cfg, probe, rules,
			)
			if err != nil || handled || !retained || body.reads == 0 {
				t.Fatalf("handled=%v retained=%v reads=%d err=%v", handled, retained, body.reads, err)
			}
			gotBody, err := io.ReadAll(outbound.Body)
			if err != nil || string(gotBody) != test.wantBody || outbound.Header.Get("X-Step") != test.wantStep {
				t.Fatalf("body=%q step=%q err=%v", gotBody, outbound.Header.Get("X-Step"), err)
			}
		})
	}
}

func TestPrepareModuleRequestAllNoneRewriteStillBuffersCompleteDecodedBody(t *testing.T) {
	tests := []struct {
		name          string
		target        string
		origins       []string
		contentCoding string
	}{
		{name: "same origin", target: "https://api.example.com/rewritten"},
		{name: "cross origin gzip", target: "https://worker.example.com/process", origins: []string{"https://worker.example.com"}, contentCoding: "gzip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {request: {url: %q}} }`, test.target)
			module := nativeRuntimeModule()
			module.Enabled = true
			module.NetworkOrigins = test.origins
			module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "none")}
			cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
			raw := []byte("payload")
			if test.contentCoding == "gzip" {
				var encoded bytes.Buffer
				writer := gzip.NewWriter(&encoded)
				_, _ = writer.Write(raw)
				_ = writer.Close()
				raw = encoded.Bytes()
			}
			body := &trackingReadCloser{reader: bytes.NewReader(raw)}
			incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
			incoming.Body = body
			incoming.ContentLength = int64(body.reader.Len())
			if test.contentCoding != "" {
				incoming.Header.Set("Content-Encoding", test.contentCoding)
			}
			probe := moduleRequestProbe(incoming, "api.example.com")
			rules := matchingScriptRules(cfg, "request", probe)

			outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
				httptest.NewRecorder(), incoming, cfg, probe, rules,
			)
			if err != nil || handled || !retained || body.reads == 0 || outbound.URL.String() != test.target || outbound.GetBody == nil {
				t.Fatalf("handled=%v retained=%v reads=%d url=%v get_body=%v err=%v", handled, retained, body.reads, outbound.URL, outbound.GetBody != nil, err)
			}
			gotBody, err := io.ReadAll(outbound.Body)
			if err != nil || string(gotBody) != "payload" || outbound.Header.Get("Content-Encoding") != "" {
				t.Fatalf("body=%q headers=%v err=%v", gotBody, outbound.Header, err)
			}
		})
	}
}

func TestPrepareModuleRequestAllNoneReplacementDrainsForLateTrailers(t *testing.T) {
	source := `function transform() { return {request: {body: "replacement"}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("original"))}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
	incoming.Proto = "HTTP/2.0"
	incoming.ProtoMajor = 2
	incoming.ProtoMinor = 0
	incoming.Body = body
	incoming.ContentLength = int64(body.reader.Len())
	incoming.Trailer = http.Header{"Grpc-Status": nil}
	body.onEOF = func() { incoming.Trailer.Set("Grpc-Status", "0") }
	probe := moduleRequestProbe(incoming, "api.example.com")
	rules := matchingScriptRules(cfg, "request", probe)

	outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
		httptest.NewRecorder(), incoming, cfg, probe, rules,
	)
	if err != nil || handled || !retained || body.reads == 0 || body.closes == 0 || outbound.GetBody == nil {
		t.Fatalf("handled=%v retained=%v reads=%d closes=%d get_body=%v err=%v", handled, retained, body.reads, body.closes, outbound.GetBody != nil, err)
	}
	gotBody, err := io.ReadAll(outbound.Body)
	if err != nil || string(gotBody) != "replacement" || outbound.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("body=%q trailers=%v err=%v", gotBody, outbound.Trailer, err)
	}
}

func TestPrepareModuleRequestAllNoneSyntheticAndAbortSkipBody(t *testing.T) {
	t.Run("synthetic", func(t *testing.T) {
		module := nativeRuntimeModule()
		module.Enabled = true
		module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return {response: {status: 202, body: "synthetic"}} }`, "request", "none")}
		cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
		body := &trackingReadCloser{reader: bytes.NewReader([]byte("original"))}
		incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
		incoming.Body = body
		incoming.ContentLength = int64(body.reader.Len())
		probe := moduleRequestProbe(incoming, "api.example.com")
		rules := matchingScriptRules(cfg, "request", probe)
		recorder := httptest.NewRecorder()

		outbound, handled, retained, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
			recorder, incoming, cfg, probe, rules,
		)
		if err != nil || !handled || retained || outbound != nil || body.reads != 0 || body.closes != 0 {
			t.Fatalf("outbound=%v handled=%v retained=%v reads=%d closes=%d err=%v", outbound, handled, retained, body.reads, body.closes, err)
		}
		response := recorder.Result()
		defer response.Body.Close()
		responseBody, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusAccepted || string(responseBody) != "synthetic" {
			t.Fatalf("status=%d body=%q", response.StatusCode, responseBody)
		}
	})

	t.Run("abort", func(t *testing.T) {
		module := nativeRuntimeModule()
		module.Enabled = true
		module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return {abort: true} }`, "request", "none")}
		cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
		body := &trackingReadCloser{reader: bytes.NewReader([]byte("original"))}
		incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", nil)
		incoming.Body = body
		incoming.ContentLength = int64(body.reader.Len())
		probe := moduleRequestProbe(incoming, "api.example.com")
		rules := matchingScriptRules(cfg, "request", probe)
		panicked := false
		func() {
			defer func() {
				panicked = recover() == http.ErrAbortHandler
			}()
			_, _, _, _ = (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequestWithRules(
				httptest.NewRecorder(), incoming, cfg, probe, rules,
			)
		}()
		if !panicked || body.reads != 0 || body.closes != 0 {
			t.Fatalf("panicked=%v reads=%d closes=%d", panicked, body.reads, body.closes)
		}
	})
}

func TestAllNoneSyntheticRespondsWithoutRequestingExpectContinueBody(t *testing.T) {
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(
		`function transform() { return {response: {status: 202, body: "synthetic"}} }`, "request", "none",
	)}
	module.Scripts[0].Match.Schemes = []string{"http"}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, handled, err := proxy.prepareModuleRequest(w, request, cfg, "api.example.com")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if !handled {
			http.Error(w, "request was not handled", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprint(connection, "POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 7\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusAccepted || string(body) != "synthetic" {
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, body, err)
	}
}

func TestModuleResultBodiesRespectActionAndGlobalLimits(t *testing.T) {
	requestCases := []struct {
		name   string
		source string
	}{
		{name: "request replacement", source: `function transform() { return {request: {body: "x".repeat(1025)}} }`},
		{name: "synthetic response", source: `function transform() { return {response: {body: "x".repeat(1025)}} }`},
	}
	for _, test := range requestCases {
		t.Run(test.name, func(t *testing.T) {
			module := nativeRuntimeModule()
			module.Enabled = true
			rule := nativeRuntimeRule(test.source, "request", "none")
			rule.MaxBodyBytes = 1024
			module.Scripts = []ScriptRule{rule}
			cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
			incoming := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
			if _, _, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
				httptest.NewRecorder(), incoming, cfg, "api.example.com",
			); err == nil || !strings.Contains(err.Error(), "result body exceeds action limit") {
				t.Fatalf("result body limit error=%v", err)
			}
		})
	}

	t.Run("response replacement", func(t *testing.T) {
		source := `function transform() { return {response: {body: "x".repeat(1025)}} }`
		module := nativeRuntimeModule()
		module.Enabled = true
		rule := nativeRuntimeRule(source, "response", "none")
		rule.MaxBodyBytes = 1024
		module.Scripts = []ScriptRule{rule}
		cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream"))}
		rules := matchingScriptRules(cfg, "response", scriptMessage{URL: request.URL.String(), Method: request.Method, StatusCode: response.StatusCode})
		if _, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, rules); err == nil || !strings.Contains(err.Error(), "result body exceeds action limit") {
			t.Fatalf("result body limit error=%v", err)
		}
	})

	if err := validateModuleResultBodySize("io.example.fixture", "action", "request", maxModuleHTTPBody, maxModuleHTTPBody+1); err == nil || !strings.Contains(err.Error(), "exceeds 67108864 bytes") {
		t.Fatalf("global result body limit error=%v", err)
	}
}

func BenchmarkPrepareModuleRequestBodyMode(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1<<20)
	for _, bodyMode := range []string{"none", "text"} {
		b.Run(bodyMode, func(b *testing.B) {
			source := `function transform() {}`
			module := nativeRuntimeModule()
			module.Enabled = true
			module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", bodyMode)}
			cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
			runtime, err := compileScriptConfig(cfg)
			if err != nil {
				b.Fatal(err)
			}
			cfg.runtime = runtime
			proxy := &interceptProxy{scripts: newScriptRuntime()}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/upload", bytes.NewReader(payload))
				outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, cfg, "api.example.com")
				if err != nil || handled {
					b.Fatalf("handled=%v err=%v", handled, err)
				}
				_ = outbound.Body.Close()
			}
		})
	}
}

func TestTransformModuleResponseUsesPrecomputedRules(t *testing.T) {
	source := `function transform() { return {response: {body: "changed"}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "response", "text")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("original"))}
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}

	transformed, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, nil)
	if err != nil || transformed != nil {
		t.Fatalf("precomputed miss transformed response: transformed=%+v err=%v", transformed, err)
	}
	if body.reads != 0 {
		t.Fatalf("precomputed miss read response body %d times", body.reads)
	}
}

func TestTransformModuleResponseExposesAndReplacesTrailers(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  if (context.response.trailers["Grpc-Status"] !== "0") throw new Error("missing upstream trailer")
  return {response: {trailers: {"Grpc-Status": "7", "Grpc-Message": "blocked"}}}
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "response", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1", nil)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Trailer:    http.Header{"Grpc-Status": {"0"}},
		Body:       io.NopCloser(strings.NewReader("payload")),
	}
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	responseRules := matchingScriptRules(cfg, "response", scriptMessage{
		URL: request.URL.String(), Method: request.Method, StatusCode: response.StatusCode,
	})
	transformed, err := proxy.transformModuleResponse(request, response, cfg, responseRules)
	if err != nil {
		t.Fatal(err)
	}
	if transformed == nil || transformed.Trailer.Get("Grpc-Status") != "7" || transformed.Trailer.Get("Grpc-Message") != "blocked" {
		t.Fatalf("transformed response = %+v", transformed)
	}
}

func TestRequestActionSyntheticResponsePublishesTrailers(t *testing.T) {
	t.Parallel()
	source := `function transform() {
  return {response: {status: 200, body: "synthetic", trailers: {"Grpc-Status": "0"}}}
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "request", "text")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	recorder := httptest.NewRecorder()
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(recorder, request, cfg, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !handled || outbound != nil {
		t.Fatalf("handled=%v outbound=%v", handled, outbound)
	}
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "synthetic" || response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("body=%q trailers=%v", body, response.Trailer)
	}
}

func TestWriteBufferedModuleResponsePublishesTrailers(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	headers := http.Header{
		"Content-Encoding": {"gzip"},
		"Content-Length":   {"999"},
		"Content-Type":     {"application/grpc"},
	}
	trailers := http.Header{
		"Grpc-Message": {"complete"},
		"Grpc-Status":  {"0"},
		"X-Final":      {"one", "two"},
	}
	if err := writeBufferedModuleResponse(recorder, http.MethodGet, http.StatusOK, headers, trailers, []byte("payload")); err != nil {
		t.Fatal(err)
	}

	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "payload" || response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if response.Header.Get("Content-Encoding") != "" || response.Header.Get("Content-Length") != "" {
		t.Fatalf("framing headers = %v", response.Header)
	}
	if response.Trailer.Get("Grpc-Status") != "0" || response.Trailer.Get("Grpc-Message") != "complete" {
		t.Fatalf("gRPC trailers = %v", response.Trailer)
	}
	if values := response.Trailer.Values("X-Final"); len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("multi-value trailer = %v", values)
	}
}

func TestStreamingResponsePublishesTrailersAfterBodyEOF(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	trailers := http.Header{"Grpc-Status": nil}
	declared := declareResponseTrailers(recorder.Header(), trailers)
	recorder.WriteHeader(http.StatusOK)
	_, _ = recorder.Write([]byte("payload"))
	trailers.Set("Grpc-Status", "0")
	publishResponseTrailers(recorder.Header(), trailers, declared)

	response := recorder.Result()
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("streamed trailer = %v", response.Trailer)
	}
}

func TestBufferedModuleResponseTrailersCrossHTTPWire(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if err := writeBufferedModuleResponse(
					w,
					request.Method,
					http.StatusOK,
					http.Header{"Content-Type": {"application/grpc"}},
					http.Header{"Grpc-Status": {"0"}, "Grpc-Message": {"complete"}},
					[]byte("payload"),
				); err != nil {
					panic(http.ErrAbortHandler)
				}
			})
			server := httptest.NewUnstartedServer(handler)
			if protocol == "http2" {
				server.EnableHTTP2 = true
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()

			response, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatal(err)
			}
			if protocol == "http2" && response.ProtoMajor != 2 {
				t.Fatalf("protocol = %s", response.Proto)
			}
			if response.Trailer.Get("Grpc-Status") != "0" || response.Trailer.Get("Grpc-Message") != "complete" {
				t.Fatalf("wire trailers = %v", response.Trailer)
			}
		})
	}
}

func TestBufferedBodylessResponsesCrossHTTPWire(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		for _, status := range []int{http.StatusNoContent, http.StatusNotModified} {
			name := fmt.Sprintf("%s/%d", protocol, status)
			t.Run(name, func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					if err := writeBufferedModuleResponse(w, request.Method, status, nil, nil, nil); err != nil {
						panic(err)
					}
				})
				server := httptest.NewUnstartedServer(handler)
				if protocol == "http2" {
					server.EnableHTTP2 = true
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()

				response, err := server.Client().Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if _, err := io.ReadAll(response.Body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != status {
					t.Fatalf("status=%d", response.StatusCode)
				}
			})
		}
	}
	if err := writeBufferedModuleResponse(httptest.NewRecorder(), http.MethodGet, http.StatusNoContent, nil, nil, []byte("forbidden")); !errors.Is(err, http.ErrBodyNotAllowed) {
		t.Fatalf("non-empty 204 body error = %v", err)
	}
	for _, test := range []struct {
		method string
		status int
	}{
		{method: http.MethodHead, status: http.StatusOK},
		{method: http.MethodGet, status: http.StatusNoContent},
		{method: http.MethodGet, status: http.StatusNotModified},
	} {
		err := writeBufferedModuleResponse(
			httptest.NewRecorder(), test.method, test.status, nil,
			http.Header{"Grpc-Status": {"0"}}, nil,
		)
		if err == nil {
			t.Fatalf("bodyless response accepted trailers: method=%s status=%d", test.method, test.status)
		}
	}
}

func TestLateStreamingTrailersCrossHTTP2Wire(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		trailers := make(http.Header)
		w.Header().Set("Content-Length", "7")
		declared := declareResponseTrailers(w.Header(), trailers)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
		trailers.Set("Grpc-Status", "0")
		publishResponseTrailers(w.Header(), trailers, declared)
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("protocol = %s", response.Proto)
	}
	if response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("wire trailers = %v", response.Trailer)
	}
}

func TestDeclaredStreamingTrailersCrossHTTP1Wire(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		trailers := http.Header{"Grpc-Status": nil}
		declared := declareResponseTrailers(w.Header(), trailers)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
		trailers.Set("Grpc-Status", "0")
		publishResponseTrailers(w.Header(), trailers, declared)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 1 {
		t.Fatalf("protocol = %s", response.Proto)
	}
	if response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("wire trailers = %v", response.Trailer)
	}
}

func TestUnannouncedHTTP2TrailerCrossesToHTTP1(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "7")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	initialTrailerCount := make(chan int, 1)
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response, err := upstream.Client().Get(upstream.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		initialTrailerCount <- len(response.Trailer)
		if err := writeStreamingProxyResponse(w, 1, http.MethodGet, response); err != nil {
			panic(http.ErrAbortHandler)
		}
	}))
	defer downstream.Close()

	response, err := downstream.Client().Get(downstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if count := <-initialTrailerCount; count != 0 {
		t.Fatalf("upstream announced %d trailers before EOF", count)
	}
	if string(body) != "payload" || response.ContentLength != -1 || !containsString(response.TransferEncoding, "chunked") {
		t.Fatalf("body=%q content_length=%d transfer_encoding=%v", body, response.ContentLength, response.TransferEncoding)
	}
	if response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("wire trailers = %v", response.Trailer)
	}
}

func TestStreamingResponseCopyFailureDoesNotPublishTrailers(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	response := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 2,
		Header:     http.Header{"Content-Length": {"20"}},
		Trailer:    http.Header{"Grpc-Status": {"0"}},
		Body: io.NopCloser(io.MultiReader(
			strings.NewReader("partial"),
			iotest.ErrReader(errors.New("upstream failed")),
		)),
	}
	if err := writeStreamingProxyResponse(recorder, 1, http.MethodGet, response); err == nil {
		t.Fatal("copy failure was ignored")
	}
	written := recorder.Result()
	defer written.Body.Close()
	if written.Trailer.Get("Grpc-Status") != "" {
		t.Fatalf("success trailer was published after a copy failure: %v", written.Trailer)
	}
}

func TestStreamingBodylessResponsePreservesContentLength(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		method string
		status int
	}{
		{name: "HEAD", method: http.MethodHead, status: http.StatusOK},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			response := &http.Response{
				StatusCode: test.status,
				ProtoMajor: 2,
				Header:     http.Header{"Content-Length": {"7"}},
				Body:       http.NoBody,
			}
			if err := writeStreamingProxyResponse(recorder, 1, test.method, response); err != nil {
				t.Fatal(err)
			}
			if got := recorder.Result().Header.Get("Content-Length"); got != "7" {
				t.Fatalf("Content-Length = %q", got)
			}
		})
	}
}

func TestBufferedResponseWriteFailuresDoNotPublishTrailers(t *testing.T) {
	t.Parallel()
	writeFailure := errors.New("write failed")
	flushFailure := errors.New("flush failed")
	for _, test := range []struct {
		name       string
		writeLimit int
		writeErr   error
		flushErr   error
	}{
		{name: "short write", writeLimit: 3},
		{name: "write error", writeLimit: -1, writeErr: writeFailure},
		{name: "flush error", writeLimit: -1, flushErr: flushFailure},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			writer := &controlledResponseWriter{
				header:     make(http.Header),
				writeLimit: test.writeLimit,
				writeErr:   test.writeErr,
				flushErr:   test.flushErr,
			}
			err := writeBufferedModuleResponse(
				writer,
				http.MethodGet,
				http.StatusOK,
				http.Header{"Content-Type": {"application/grpc"}},
				http.Header{"Grpc-Status": {"0"}},
				[]byte("payload"),
			)
			if err == nil {
				t.Fatal("buffered response failure was ignored")
			}
			if writer.header.Get("Grpc-Status") != "" {
				t.Fatalf("success trailer was published after failure: %v", writer.header)
			}
		})
	}
}

func TestStreamingFlushFailureDoesNotPublishTrailers(t *testing.T) {
	t.Parallel()
	writer := &controlledResponseWriter{
		header:     make(http.Header),
		writeLimit: -1,
		flushErr:   errors.New("flush failed"),
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 2,
		Header:     http.Header{"Content-Length": {"7"}},
		Trailer:    http.Header{"Grpc-Status": {"0"}},
		Body:       io.NopCloser(strings.NewReader("payload")),
	}
	if err := writeStreamingProxyResponse(writer, 1, http.MethodGet, response); err == nil {
		t.Fatal("streaming flush failure was ignored")
	}
	if writer.header.Get("Grpc-Status") != "" {
		t.Fatalf("success trailer was published after flush failure: %v", writer.header)
	}
}

func TestStreamingResponseRejectsUnsafeTrailers(t *testing.T) {
	t.Parallel()
	tooMany := make(http.Header, maxScriptHeaderFields+1)
	for index := 0; index <= maxScriptHeaderFields; index++ {
		tooMany[fmt.Sprintf("X-Trailer-%03d", index)] = nil
	}
	for name, trailers := range map[string]http.Header{
		"field count": tooMany,
		"duplicates":  {"Grpc-Status": {"0"}, "grpc-status": {"1"}},
	} {
		name, trailers := name, trailers
		t.Run(name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 2,
				Header:     make(http.Header),
				Trailer:    trailers,
				Body:       http.NoBody,
			}
			if err := writeStreamingProxyResponse(httptest.NewRecorder(), 2, http.MethodGet, response); err == nil {
				t.Fatal("unsafe announced trailers were accepted")
			}
		})
	}

	lateTrailers := make(http.Header)
	response := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 2,
		Header:     make(http.Header),
		Trailer:    lateTrailers,
		Body: &trailerSettingReadCloser{
			reader:  strings.NewReader("payload"),
			trailer: lateTrailers,
		},
	}
	writer := httptest.NewRecorder()
	if err := writeStreamingProxyResponse(writer, 2, http.MethodGet, response); err == nil {
		t.Fatal("oversized late trailer was accepted")
	}
	if writer.Header().Get("X-Oversized") != "" || writer.Header().Get(http.TrailerPrefix+"X-Oversized") != "" {
		t.Fatalf("oversized late trailer was published: %v", writer.Header())
	}
}

func TestStreamingBodylessResponseRejectsTrailers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method string
		status int
	}{
		{method: http.MethodHead, status: http.StatusOK},
		{method: http.MethodGet, status: http.StatusNoContent},
		{method: http.MethodGet, status: http.StatusNotModified},
	} {
		announced := &http.Response{
			StatusCode: test.status,
			ProtoMajor: 2,
			Header:     make(http.Header),
			Trailer:    http.Header{"Grpc-Status": {"0"}},
			Body:       http.NoBody,
		}
		if err := writeStreamingProxyResponse(httptest.NewRecorder(), 2, test.method, announced); err == nil {
			t.Fatalf("bodyless response accepted an announced trailer: method=%s status=%d", test.method, test.status)
		}
	}

	lateTrailers := make(http.Header)
	late := &http.Response{
		StatusCode: http.StatusNotModified,
		ProtoMajor: 2,
		Header:     make(http.Header),
		Trailer:    lateTrailers,
		Body: &trailerSettingReadCloser{
			reader:  strings.NewReader(""),
			trailer: lateTrailers,
			name:    "Grpc-Status",
			value:   "0",
		},
	}
	writer := httptest.NewRecorder()
	if err := writeStreamingProxyResponse(writer, 2, http.MethodGet, late); err == nil {
		t.Fatal("bodyless response accepted a late trailer")
	}
	if writer.Header().Get("Grpc-Status") != "" || writer.Header().Get(http.TrailerPrefix+"Grpc-Status") != "" {
		t.Fatalf("bodyless trailer was published: %v", writer.Header())
	}
}

type controlledResponseWriter struct {
	header     http.Header
	status     int
	body       bytes.Buffer
	writeLimit int
	writeErr   error
	flushErr   error
}

type trailerSettingReadCloser struct {
	reader  *strings.Reader
	trailer http.Header
	name    string
	value   string
	set     bool
}

func (r *trailerSettingReadCloser) Read(buffer []byte) (int, error) {
	read, err := r.reader.Read(buffer)
	if errors.Is(err, io.EOF) && !r.set {
		name := r.name
		value := r.value
		if name == "" {
			name = "X-Oversized"
			value = strings.Repeat("x", maxScriptHeaderValueBytes+1)
		}
		r.trailer.Set(name, value)
		r.set = true
	}
	return read, err
}

func (r *trailerSettingReadCloser) Close() error {
	return nil
}

func (w *controlledResponseWriter) Header() http.Header {
	return w.header
}

func (w *controlledResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *controlledResponseWriter) Write(body []byte) (int, error) {
	limit := len(body)
	if w.writeLimit >= 0 && w.writeLimit < limit {
		limit = w.writeLimit
	}
	_, _ = w.body.Write(body[:limit])
	return limit, w.writeErr
}

func (w *controlledResponseWriter) FlushError() error {
	return w.flushErr
}
