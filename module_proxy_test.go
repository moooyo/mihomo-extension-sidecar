package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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
	"sync/atomic"
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
	// Bytes were bounded; time was not. An upstream that accepts a request and
	// never answers held a handler goroutine and its mihomo SOCKS connection for
	// as long as it liked.
	if transport.ResponseHeaderTimeout != upstreamResponseHeaderTimeout ||
		transport.TLSHandshakeTimeout != upstreamHandshakeTimeout {
		t.Fatalf("upstream leg is not bounded in time: %+v", transport)
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

	outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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
	// quic-go's shape, not httptest's. Its H3 server attaches a non-nil Body and
	// leaves ContentLength at -1 whenever no content-length header was sent, so
	// a plain GET is indistinguishable from an undeclared upload by those two
	// fields alone. httptest gives http.NoBody and 0, which is the one shape the
	// production server never produces -- and the shape that hid this.
	incoming.Body = io.NopCloser(bytes.NewReader(nil))
	incoming.ContentLength = -1
	probe := moduleRequestProbe(incoming, "api.example.com")

	outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
		httptest.NewRecorder(), incoming, Config{}, probe, nil,
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	// Nothing was buffered, so nothing may be held. Retaining a zero-byte buffer
	// kept the whole undeclared-length reservation for the round trip, which on
	// HTTP/3 is every request.
	if retained {
		t.Fatal("a bodyless HTTP/3 request retained its body reservation; H3 interception serializes to one request at a time")
	}
	if err := resetHTTP3RequestBodyForReplay(outbound); err != nil {
		t.Fatal(err)
	}
	if outbound.Body != nil && outbound.ContentLength != 0 {
		t.Fatalf("bodyless replay retained a non-empty body %T", outbound.Body)
	}
}

// A request with zero matched rules is forwarded byte-for-byte, so an
// undeclared length is no reason to hold it in memory. Both shapes that carry
// one -- chunked HTTP/1.1 and HTTP/2 -- used to be fully read and to hold one of
// the two process-wide body slots for as long as the client took to send.
func TestPrepareModuleRequestStreamsUnknownLengthUnmatchedBody(t *testing.T) {
	cases := []struct {
		name             string
		protoMajor       int
		transferEncoding []string
	}{
		{name: "chunked HTTP/1.1", protoMajor: 1, transferEncoding: []string{"chunked"}},
		{name: "HTTP/2 without a declared length", protoMajor: 2},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
			incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
			incoming.Body = body
			incoming.ContentLength = -1
			incoming.ProtoMajor = testCase.protoMajor
			incoming.TransferEncoding = testCase.transferEncoding

			proxy := &interceptProxy{scripts: newScriptRuntime()}
			_, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
			if err != nil || handled {
				t.Fatalf("handled=%v err=%v", handled, err)
			}
			if body.reads != 0 {
				t.Fatalf("the body was read into memory: reads=%d", body.reads)
			}
			if requestNeedsModuleBodyReservation(incoming, nil) {
				t.Fatal("a streamed body still reserved a body slot")
			}
		})
	}
}

// HTTP/3 keeps buffering, and the guard that keeps it buffering must stay.
// roundTripHTTP3 replays the request against QUIC version 2 after a version
// negotiation error, and resetHTTP3RequestBodyForReplay hard-errors without
// GetBody -- which only the buffered path supplies.
func TestPrepareModuleRequestBuffersUnknownLengthHTTP3Body(t *testing.T) {
	body := &trackingReadCloser{reader: bytes.NewReader([]byte("payload"))}
	incoming := httptest.NewRequest(http.MethodPost, "http://api.example.com/upload", nil)
	incoming.Body = body
	incoming.ContentLength = -1
	incoming.ProtoMajor = 3

	proxy := &interceptProxy{scripts: newScriptRuntime()}
	outbound, handled, err := proxy.prepareModuleRequest(httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if body.reads == 0 || outbound.GetBody == nil {
		t.Fatalf("an HTTP/3 body must stay replayable: reads=%d getBody=%v", body.reads, outbound.GetBody != nil)
	}
	if !requestNeedsModuleBodyReservation(incoming, nil) {
		t.Fatal("a buffered HTTP/3 body did not reserve a body slot")
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
		config: store, scripts: newScriptRuntime(), bodyBudget: newModuleBodyBudget(maxModuleBodyBudgetBytes),
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

	outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

			outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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
		config: store, scripts: newScriptRuntime(statePath), bodyBudget: newModuleBodyBudget(maxModuleBodyBudgetBytes),
	}
	// Exhaust the whole budget so the next reservation has to wait.
	proxy.bodyBudget.acquire(context.Background(), maxModuleBodyBudgetBytes, time.Second)
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

		outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

		outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

		_, _, _, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

			outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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
		network       bool
		contentCoding string
	}{
		{name: "same origin", target: "https://api.example.com/rewritten"},
		{name: "cross origin gzip", target: "https://worker.example.com/process", network: true, contentCoding: "gzip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {request: {url: %q}} }`, test.target)
			module := nativeRuntimeModule()
			module.Enabled = true
			module.Network = test.network
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

			outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

	outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

		outbound, handled, retained, err := prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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
			_, _, _, _ = prepareForTest(&interceptProxy{scripts: newScriptRuntime()},
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

// TestStreamingResponseDropsUnrepublishableOriginTrailers pins the distinction
// wireTrailers draws against the budget checks above. The names
// validResponseTrailerName rejects are the RFC 7230 4.1.2 set a proxy must not
// forward in a trailer section: an origin that emits one is quirky, not hostile,
// so the field is dropped. Refusing instead failed the whole exchange -- and on
// the passthrough leg ServeHTTP turns that error into
// panic(http.ErrAbortHandler), tearing the client connection down before a byte
// is written, for a response this process was only relaying.
func TestStreamingResponseDropsUnrepublishableOriginTrailers(t *testing.T) {
	t.Parallel()
	response := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 2,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Trailer:    http.Header{"Cache-Control": {"no-store"}, "Grpc-Status": {"0"}},
		Body:       io.NopCloser(strings.NewReader("payload")),
	}
	writer := httptest.NewRecorder()
	if err := writeStreamingProxyResponse(writer, 2, http.MethodGet, response); err != nil {
		t.Fatalf("a relayable response was refused over an origin trailer: %v", err)
	}
	if got := writer.Body.String(); got != "payload" {
		t.Fatalf("body = %q", got)
	}
	header := writer.Header()
	if header.Get("Cache-Control") != "" || header.Get(http.TrailerPrefix+"Cache-Control") != "" {
		t.Fatalf("unrepublishable trailer was forwarded: %v", header)
	}
	if header.Get("Grpc-Status") == "" && header.Get(http.TrailerPrefix+"Grpc-Status") == "" {
		t.Fatalf("legitimate trailer was dropped alongside it: %v", header)
	}
}

// TestRequestBodyDecodeIsBoundedByTheActionLimit pins the request half of
// moduleBodyReadLimit. The wire read was already bounded by the action limit
// while the decode used the 64 MiB process cap, so an action declaring
// maxBodyBytes 1024 still let a client expand a body far past it while holding
// one of the two body slots. The response path keeps the global cap on purpose.
func TestRequestBodyDecodeIsBoundedByTheActionLimit(t *testing.T) {
	t.Parallel()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte("a"), 64<<10)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	const actionLimit = int64(1024)
	if int64(compressed.Len()) >= actionLimit {
		t.Fatalf("fixture must stay under the wire limit to exercise the decode bound, got %d bytes", compressed.Len())
	}
	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1", bytes.NewReader(compressed.Bytes()))
	incoming.Header.Set("Content-Encoding", "gzip")
	if _, err := readDecodedModuleRequestBody(httptest.NewRecorder(), incoming, actionLimit); err == nil {
		t.Fatal("a decoded request body far past the action limit was accepted")
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

// The read bound is the largest limit among the actions that actually read a
// body. An action in "none" mode reads none, so it must not contribute a
// ceiling -- that is the mistake TestResponseActionLimitDoesNotBoundTheUpstreamBody
// exists to catch, expressed here at the level of the choice itself.
// An origin is not bound by the budget written for what a script may invent.
//
// exportedHeaders limits field and value counts as well as bytes, and those
// counts are calibrated for a script. Running it over inbound traffic meant a
// response carrying more than maxScriptHeaderFields fields was refused -- and on
// the response path the upstream exchange has already succeeded, so that refusal
// reaches the client as a 502 for a response the origin answered perfectly well.
// The wire bound is maxWireHeaderBytes, which net/http enforced before any of
// this ran.
func TestAWideOriginHeaderBlockIsNotJudgedByTheScriptBudget(t *testing.T) {
	t.Parallel()
	// Changes the status rather than the headers: a script that returns headers
	// replaces the whole set, which would hide whether the projection carried the
	// origin's own fields through.
	source := `function transform() { return {response: {status: 201}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	rule := nativeRuntimeRule(source, "response", "none")
	module.Scripts = []ScriptRule{rule}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	scripts := []matchedScriptRule{{Module: module, Rule: rule}}

	// Well past the script field budget, and still a small block on the wire --
	// comfortably inside what net/http already accepted.
	wide := make(http.Header, maxScriptHeaderFields+64)
	for index := 0; index < maxScriptHeaderFields+64; index++ {
		wide[fmt.Sprintf("X-Origin-%04d", index)] = []string{"1"}
	}
	if len(wide) <= maxScriptHeaderFields {
		t.Fatalf("fixture built %d fields, want more than the %d field script budget", len(wide), maxScriptHeaderFields)
	}
	// The split itself: the same block that the script-output validator refuses
	// is carried by the wire projection. Before they were one function, this
	// rejection was what an origin got.
	if _, err := exportedHeaders(wide); err == nil {
		t.Fatal("the script header validator accepted a block wider than its own field budget")
	}
	if len(wireHeaders(wide)) != len(wide) {
		t.Fatal("the wire projection dropped fields")
	}

	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	response := &http.Response{
		StatusCode: http.StatusOK, Header: wide, Body: io.NopCloser(strings.NewReader("body")),
	}
	transformed, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, scripts)
	if err != nil {
		t.Fatalf("a wide origin header block was refused: %v", err)
	}
	if transformed == nil || transformed.StatusCode != 201 {
		t.Fatalf("the action did not run over a wide header block: %+v", transformed)
	}
	if got := transformed.Header.Get("X-Origin-0100"); got != "1" {
		t.Fatalf("an origin header was dropped in projection: X-Origin-0100=%q", got)
	}
}

// The request path takes the same projection, so a client sending a wide header
// block must reach the upstream leg rather than a 502 built from a script limit.
func TestAWideClientHeaderBlockReachesUpstream(t *testing.T) {
	t.Parallel()
	incoming := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1", nil)
	for index := 0; index < maxScriptHeaderFields+64; index++ {
		incoming.Header.Set(fmt.Sprintf("X-Client-%04d", index), "1")
	}

	outbound, handled, err := (&interceptProxy{scripts: newScriptRuntime()}).prepareModuleRequest(
		httptest.NewRecorder(), incoming, Config{}, "api.example.com")
	if err != nil || handled {
		t.Fatalf("a wide client header block was refused: handled=%v err=%v", handled, err)
	}
	if got := outbound.Header.Get("X-Client-0100"); got != "1" {
		t.Fatalf("a client header was dropped in projection: X-Client-0100=%q", got)
	}
}

// prepareForTest keeps the four-value shape these tests were written against
// now that preparation returns a named result.
func prepareForTest(
	p *interceptProxy,
	w http.ResponseWriter,
	incoming *http.Request,
	cfg Config,
	probe scriptMessage,
	rules []matchedScriptRule,
) (*http.Request, bool, bool, error) {
	prepared, err := p.prepareModuleRequestWithRules(w, incoming, cfg, probe, rules)
	return prepared.outbound, prepared.handled, prepared.bodyBufferRetained, err
}

// forwardRequestHeadersForTest computes the candidate set the production caller
// computes while building the outbound request.
func forwardRequestHeadersForTest(cfg Config, message scriptMessage) http.Header {
	return forwardRequestHeaders(message, matchingScriptRulesWithStatus(cfg, "response", message, false))
}

func TestModuleBodyReadLimitIgnoresActionsThatDoNotReadTheBody(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	rule := func(mode string, max int64) matchedScriptRule {
		r := nativeRuntimeRule(`function transform() { return {} }`, "response", mode)
		r.MaxBodyBytes = max
		return matchedScriptRule{Module: module, Rule: r}
	}
	cases := []struct {
		name  string
		rules []matchedScriptRule
		want  int64
	}{
		{name: "no rules at all forwards, so the global cap stands", rules: nil, want: maxModuleHTTPBody},
		{
			name:  "a none-mode action never bounds the read",
			rules: []matchedScriptRule{rule("none", 1024)},
			want:  maxModuleHTTPBody,
		},
		{
			name:  "a reading action bounds it to its own limit",
			rules: []matchedScriptRule{rule("text", 1<<20)},
			want:  1 << 20,
		},
		{
			name:  "the largest reader wins, so every action still gets its bytes",
			rules: []matchedScriptRule{rule("text", 1<<20), rule("binary", 8<<20)},
			want:  8 << 20,
		},
		{
			name:  "a none-mode action alongside a reader does not shrink it",
			rules: []matchedScriptRule{rule("none", 1024), rule("text", 4<<20)},
			want:  4 << 20,
		},
		{
			name:  "a limit above the global cap cannot raise it",
			rules: []matchedScriptRule{rule("text", maxModuleHTTPBody*2)},
			want:  maxModuleHTTPBody,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := moduleBodyReadLimit(testCase.rules); got != testCase.want {
				t.Fatalf("read limit = %d, want %d", got, testCase.want)
			}
		})
	}
}

// MaxBodyBytes bounds the projection an action is handed, not what the upstream
// is allowed to send. Reading the upstream response with it made the smallest
// legal value a ceiling on the whole response: readBounded failed before the
// per-rule check could exempt a "none" mode action, and because the upstream
// request had already succeeded the client got a 502 for a response the
// extension never even looked at.
func TestResponseActionLimitDoesNotBoundTheUpstreamBody(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {response: {headers: {"X-Marked": ["1"]}}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	rule := nativeRuntimeRule(source, "response", "none")
	rule.MaxBodyBytes = 1024
	module.Scripts = []ScriptRule{rule}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	scripts := []matchedScriptRule{{Module: module, Rule: rule}}

	for _, size := range []int{1024, 1025, 64 << 10} {
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
		response := &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), size))),
		}
		transformed, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, scripts)
		if err != nil {
			t.Fatalf("a %d byte upstream body failed a body_mode=none action with max_body_bytes=%d: %v", size, rule.MaxBodyBytes, err)
		}
		if transformed == nil || transformed.Header.Get("X-Marked") != "1" {
			t.Fatalf("a %d byte upstream body did not run the action: transformed=%+v", size, transformed)
		}
	}

	// The per-rule limit still applies to an action that does read the body.
	reading := rule
	reading.BodyMode = "text"
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	response := &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 1025))),
	}
	_, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, []matchedScriptRule{{Module: module, Rule: reading}})
	if err == nil {
		t.Fatal("a body_mode=text action accepted a body over its own max_body_bytes")
	}
}

// An origin is free to ignore the Accept-Encoding this sidecar sends. When it
// answers in a coding decodeContentBody does not implement, the response cannot
// be projected into a script message — but refusing to serve it turned the
// origin's choice into a 502 for a request that had already succeeded. It
// streams through instead, untouched, with the skip reported per action.
func TestUndecodableUpstreamCodingStreamsThroughInsteadOf502(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {response: {body: "rewritten"}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	rule := nativeRuntimeRule(source, "response", "text")
	module.Scripts = []ScriptRule{rule}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	scripts := []matchedScriptRule{{Module: module, Rule: rule}}

	for _, encoding := range []string{"zstd", "gzip, br"} {
		payload := []byte("bytes-the-sidecar-cannot-decode")
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
		header := make(http.Header)
		header.Set("Content-Encoding", encoding)
		response := &http.Response{
			StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(bytes.NewReader(payload)),
		}
		transformed, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, scripts)
		if err != nil {
			t.Fatalf("Content-Encoding %q became an error: %v", encoding, err)
		}
		if transformed != nil {
			t.Fatalf("Content-Encoding %q produced a transformed response: %+v", encoding, transformed)
		}
		// The caller streams response.Body, so every byte the origin sent has to
		// still be there along with the coding that describes them.
		streamed, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("Content-Encoding %q: replaying the body: %v", encoding, err)
		}
		if !bytes.Equal(streamed, payload) {
			t.Fatalf("Content-Encoding %q streamed %q, want %q", encoding, streamed, payload)
		}
		if got := response.Header.Get("Content-Encoding"); got != encoding {
			t.Fatalf("Content-Encoding rewritten to %q, want %q", got, encoding)
		}
	}
}

// The passthrough branch above must not become a way for an origin to make an
// action not run. Landing it before max_body_bytes stopped bounding the upstream
// read would have done exactly that: a body over the rule's limit failed inside
// decodeContentBody, which returns the same error for "cannot decode" as for
// "too large", so gzipping a response silently skipped the action that plaintext
// would have run. With the read bounded by the global cap instead, a decodable
// body always reaches the per-rule check and both encodings agree.
func TestGzipDoesNotLetAnOriginSkipAResponseAction(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {response: {body: "rewritten"}} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	rule := nativeRuntimeRule(source, "response", "text")
	rule.MaxBodyBytes = 1024
	module.Scripts = []ScriptRule{rule}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	scripts := []matchedScriptRule{{Module: module, Rule: rule}}

	plain := bytes.Repeat([]byte("x"), 4096)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	run := func(body []byte, encoding string) error {
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
		header := make(http.Header)
		if encoding != "" {
			header.Set("Content-Encoding", encoding)
		}
		response := &http.Response{
			StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(bytes.NewReader(body)),
		}
		transformed, err := (&interceptProxy{scripts: newScriptRuntime()}).transformModuleResponse(request, response, cfg, scripts)
		if err == nil && transformed == nil {
			t.Fatalf("Content-Encoding %q: the action was silently skipped", encoding)
		}
		return err
	}

	plainErr := run(plain, "")
	gzipErr := run(compressed.Bytes(), "gzip")
	if plainErr == nil || gzipErr == nil {
		t.Fatalf("over-limit body accepted: plain=%v gzip=%v", plainErr, gzipErr)
	}
}

// The upstream Accept-Encoding override exists so transformModuleResponse can
// decode what it is handed, and decodeContentBody understands only gzip, deflate
// and br. An exchange no response action can run on has nothing to decode, so
// forcing identity there only costs the metered origin leg its compression — and
// answers a client that explicitly refused identity with it anyway.
func TestAcceptEncodingIsPinnedOnlyWhenAResponseActionCouldRun(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {} }`
	base := nativeRuntimeModule()
	base.Enabled = true

	withRule := func(rule ScriptRule) Config {
		module := base
		module.Scripts = []ScriptRule{rule}
		return Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	}
	statusScoped := nativeRuntimeRule(source, "response", "text")
	statusScoped.Match.StatusCodes = []int{200}

	message := scriptMessage{
		URL: "https://api.example.com/v1", Method: http.MethodGet,
		Headers: http.Header{"Accept-Encoding": []string{"gzip, br"}},
	}

	// A response rule scoped to a status code still counts at request time: the
	// status is not knowable yet, so it has to be treated as a possible match.
	if got := forwardRequestHeadersForTest(withRule(statusScoped), message).Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("a status-scoped response action did not pin identity: Accept-Encoding=%q", got)
	}
	// A request-phase-only extension never reads the response body.
	if got := forwardRequestHeadersForTest(withRule(nativeRuntimeRule(source, "request", "text")), message).Get("Accept-Encoding"); got != "gzip, br" {
		t.Fatalf("a request-only extension pinned identity: Accept-Encoding=%q", got)
	}
	// So does a host this extension does not capture.
	elsewhere := message
	elsewhere.URL = "https://other.example.com/v1"
	if got := forwardRequestHeadersForTest(withRule(statusScoped), elsewhere).Get("Accept-Encoding"); got != "gzip, br" {
		t.Fatalf("an uncaptured host pinned identity: Accept-Encoding=%q", got)
	}
}

// Filtering the request-time probe by status must produce exactly what a fresh
// status-aware walk produces. That equality is the whole licence for reusing the
// probe instead of walking every rule a second time, so it is asserted
// differentially rather than assumed -- the same way the transport projection is
// checked against its naive reference.
func TestFilteredProbeEqualsAFreshStatusAwareWalk(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {} }`
	module := nativeRuntimeModule()
	module.Enabled = true

	unscoped := nativeRuntimeRule(source, "response", "text")
	unscoped.ID = "unscoped"
	okOnly := nativeRuntimeRule(source, "response", "text")
	okOnly.ID = "ok-only"
	okOnly.Match.StatusCodes = []int{200}
	errorsOnly := nativeRuntimeRule(source, "response", "text")
	errorsOnly.ID = "errors-only"
	errorsOnly.Match.StatusCodes = []int{500, 502}
	notFound := nativeRuntimeRule(source, "response", "text")
	notFound.ID = "not-found"
	notFound.Match.StatusCodes = []int{404}
	module.Scripts = []ScriptRule{unscoped, okOnly, errorsOnly, notFound}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}

	probeMessage := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet}
	candidates := matchingScriptRulesWithStatus(cfg, "response", probeMessage, false)
	if len(candidates) != 4 {
		t.Fatalf("the probe found %d candidates, want all 4", len(candidates))
	}

	for _, status := range []int{200, 404, 500, 502, 0, 204, 301} {
		fresh := matchingScriptRules(cfg, "response", scriptMessage{
			URL: probeMessage.URL, Method: probeMessage.Method, StatusCode: status,
		})
		filtered := responseRulesForStatus(candidates, status)
		if len(filtered) != len(fresh) {
			t.Fatalf("status %d: filtered %d rules, a fresh walk found %d", status, len(filtered), len(fresh))
		}
		for index := range fresh {
			if filtered[index].Rule.ID != fresh[index].Rule.ID {
				t.Fatalf("status %d: filtered[%d]=%s, fresh[%d]=%s",
					status, index, filtered[index].Rule.ID, index, fresh[index].Rule.ID)
			}
		}
	}

	// Filtering must not scribble on the candidate set: the probe is also what
	// pinned Accept-Encoding, and a later status must see it whole.
	if len(candidates) != 4 {
		t.Fatalf("filtering mutated the shared candidate set: %d left", len(candidates))
	}
}

// The request-time probe ignores status codes because none exists yet. That must
// stay an explicit argument rather than being inferred from StatusCode == 0:
// net/http accepts "HTTP/1.1 000" and hands back a response whose StatusCode is
// genuinely 0, so inferring would run a status-scoped action on exactly the
// response an operator wrote status_codes to exclude.
func TestStatusScopedRulesDoNotMatchAGenuineZeroStatus(t *testing.T) {
	t.Parallel()
	source := `function transform() { return {} }`
	module := nativeRuntimeModule()
	module.Enabled = true
	rule := nativeRuntimeRule(source, "response", "text")
	rule.Match.StatusCodes = []int{200}
	module.Scripts = []ScriptRule{rule}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}

	zero := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 0}
	if matched := matchingScriptRules(cfg, "response", zero); len(matched) != 0 {
		t.Fatalf("a status-scoped action ran on a status-0 response: %d rules matched", len(matched))
	}
	if matched := matchingScriptRulesWithStatus(cfg, "response", zero, false); len(matched) != 1 {
		t.Fatalf("the request-time probe dropped a status-scoped rule: %d rules matched", len(matched))
	}
}

type countingConn struct {
	net.Conn
	read int64
}

func (c *countingConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	atomic.AddInt64(&c.read, int64(count))
	return count, err
}

// ServeHTTP wraps r.Body to re-arm a stall deadline per read, and has to hand
// the original back before returning. net/http decides whether to drain an
// unread request body by type-asserting Request.Body to its own concrete type
// (chunkWriter.writeHeader), so a wrapper left in place makes it fall to the
// default branch and pull up to maxPostHandlerReadBytes off the wire — for an
// upload this sidecar has already rejected as oversize.
func TestOversizeUploadIsNotDrainedFromTheWire(t *testing.T) {
	cfg := validNativeConfig()
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &interceptProxy{config: store, scripts: newScriptRuntime(), bodyBudget: newModuleBodyBudget(maxModuleBodyBudgetBytes)}

	client, server := net.Pipe()
	counting := &countingConn{Conn: server}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = proxy.servePlainHTTPConnection(counting)
	}()

	header := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: %d\r\n\r\n",
		maxModuleHTTPBody+1)
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, header); err != nil {
		t.Fatal(err)
	}
	// Offer body bytes the server must not take. Writes block on an unread pipe,
	// so this stops on its own once the response has been written.
	go func() {
		chunk := bytes.Repeat([]byte("x"), 16<<10)
		for {
			if _, err := client.Write(chunk); err != nil {
				return
			}
		}
	}()

	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if !strings.Contains(status, "502") {
		t.Fatalf("oversize upload status line = %q, want 502", strings.TrimSpace(status))
	}
	consumed := atomic.LoadInt64(&counting.read) - int64(len(header))
	if consumed != 0 {
		t.Fatalf("the server drained %d body bytes of an upload it had already rejected", consumed)
	}
	_ = client.Close()
	<-served
}

// A response rule set that never reads the body must not buffer the response.
//
// moduleBodyReadLimit deliberately skips "none" mode rules, so when every
// matched rule is "none" the limit falls back to the process-wide 64 MiB and
// the whole response is held in memory. One response-phase header edit scoped
// `^/` therefore buffered every download on that host, delayed its first byte
// until the origin finished, held one of the two process body slots throughout,
// and answered 502 above the cap on an exchange that had already succeeded.
func TestResponseHeaderEditsStreamRatherThanBuffer(t *testing.T) {
	t.Parallel()
	headerRule := func(id string) matchedScriptRule {
		return matchedScriptRule{
			Module: Module{ID: "io.example.headers", CaptureHosts: []string{"api.example.com"}},
			Rule: ScriptRule{
				ID: id, Phase: "response", BodyMode: "none", TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
				Headers: &HeaderEdits{Set: map[string]string{"X-Edited": "1"}, Remove: []string{"X-Drop"}},
			},
		}
	}
	other := func(mutate func(*ScriptRule)) matchedScriptRule {
		m := headerRule("other")
		m.Rule.Headers = nil
		mutate(&m.Rule)
		return m
	}

	if !responseRulesStreamable([]matchedScriptRule{headerRule("a"), headerRule("b")}) {
		t.Fatal("a header-only rule set must stream")
	}
	if responseRulesStreamable(nil) {
		t.Fatal("an empty rule set is not a streaming decision")
	}
	for name, rule := range map[string]matchedScriptRule{
		// A script declaring "none" still receives context.response.trailers,
		// which only exist once the body reached EOF.
		"script": other(func(r *ScriptRule) { r.ScriptBody = "function transform(){return null}" }),
		"mock":   other(func(r *ScriptRule) { r.Mock = &MockResponse{Status: 200, Body: "{}"} }),
		"jq":     other(func(r *ScriptRule) { r.BodyMode = "text"; r.JQProgram = "." }),
		"replace": other(func(r *ScriptRule) {
			r.BodyMode = "text"
			r.ReplaceBody = &BodyReplace{Pattern: "a", To: "b"}
		}),
	} {
		if responseRulesStreamable([]matchedScriptRule{headerRule("a"), rule}) {
			t.Errorf("a rule set containing a %s action must not stream", name)
		}
	}
}

// The streaming edit rewrites the response's own header map and leaves framing
// alone -- the opposite of the buffered path, which must drop Content-Length
// and Content-Encoding because it decoded the body.
func TestStreamingResponseHeaderEditsPreserveFraming(t *testing.T) {
	t.Parallel()
	proxy := &interceptProxy{scripts: newScriptRuntime()}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/items", nil)
	response := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Length":   []string{"1048576"},
			"Content-Encoding": []string{"gzip"},
			"X-Drop":           []string{"gone"},
			"X-Keep":           []string{"kept"},
		},
	}
	rules := []matchedScriptRule{{
		Module: Module{ID: "io.example.headers", CaptureHosts: []string{"api.example.com"}},
		Rule: ScriptRule{
			ID: "edit", Phase: "response", BodyMode: "none", TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
			Headers: &HeaderEdits{Set: map[string]string{"X-Edited": "1"}, Remove: []string{"X-Drop"}},
		},
	}}
	if err := proxy.applyStreamingResponseHeaderEdits(request, response, Config{}, rules); err != nil {
		t.Fatal(err)
	}
	if got := response.Header.Get("X-Edited"); got != "1" {
		t.Fatalf("the edit did not apply: %v", response.Header)
	}
	if response.Header.Get("X-Drop") != "" {
		t.Fatalf("the removal did not apply: %v", response.Header)
	}
	if response.Header.Get("X-Keep") != "kept" {
		t.Fatalf("an untouched header was lost: %v", response.Header)
	}
	// Framing survives, because this path never decoded the body.
	if response.Header.Get("Content-Length") != "1048576" || response.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("framing was altered on a body this path never read: %v", response.Header)
	}
}

// Admission counts bytes, not streams.
//
// A two-slot semaphore made a bodyMode "none" proxy-compat action and a 16 MiB
// buffered response cost the same unit of a capacity of two -- and the slot is
// taken before the whole action loop runs and held across the upstream round
// trip whenever the body buffer is retained, so "two streams" meant "two
// extensions executing anywhere in this process". One slow extension starved
// every other extension's captured traffic.
func TestModuleBodyBudgetAdmitsByBytes(t *testing.T) {
	t.Parallel()
	budget := newModuleBodyBudget(1 << 20)
	ctx := context.Background()

	// Many small reservations coexist, where a capacity of two admitted two.
	for i := 0; i < 16; i++ {
		if !budget.acquire(ctx, 1<<10, time.Second) {
			t.Fatalf("reservation %d of 16 KiB against a 1 MiB budget was refused", i)
		}
	}
	// And the budget is still a budget.
	if budget.acquire(ctx, 1<<20, 20*time.Millisecond) {
		t.Fatal("a reservation past the limit was admitted")
	}
	for i := 0; i < 16; i++ {
		budget.release(1 << 10)
	}
	if !budget.acquire(ctx, 1<<20, time.Second) {
		t.Fatal("the whole budget was not free again after every release")
	}
	budget.release(1 << 20)

	// A reservation larger than the whole budget is clamped rather than refused:
	// the caller is already bounded by maxModuleHTTPBody, and refusing would
	// make the largest legal body permanently unservable.
	if !budget.acquire(ctx, 1<<30, time.Second) {
		t.Fatal("an over-large reservation was refused instead of clamped")
	}
	budget.release(1 << 30)
}

// moduleBodyReservation asks for what the request is expected to hold resident,
// not for a fixed unit.
func TestModuleBodyReservationTracksTheDeclaredLength(t *testing.T) {
	t.Parallel()
	rule := matchedScriptRule{
		Module: Module{ID: "io.example.reserve"},
		Rule:   ScriptRule{ID: "a", Phase: "request", BodyMode: "text", MaxBodyBytes: 8 << 20, TimeoutMS: 1000},
	}
	small := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1", strings.NewReader("x"))
	small.ContentLength = 1024
	if got := moduleBodyReservation(small, []matchedScriptRule{rule}); got != 8<<20 {
		t.Fatalf("reservation = %d; an action may hand back up to its own limit", got)
	}

	// A bodyless request whose action can still synthesise a response reserves
	// what that action is allowed to produce.
	none := matchedScriptRule{
		Module: rule.Module,
		Rule:   ScriptRule{ID: "b", Phase: "request", BodyMode: "none", MaxBodyBytes: 1 << 20, TimeoutMS: 1000},
	}
	bodyless := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	if got := moduleBodyReservation(bodyless, []matchedScriptRule{none}); got != 1<<20 {
		t.Fatalf("bodyless reservation = %d, want the action's own limit", got)
	}
}

// The response leg reserves what it will read, not what the actions declare.
//
// moduleBodyReadLimit deliberately skips bodyMode "none" rules and falls back to
// the process-wide cap when none remains, so an all-"none" response rule set
// reads up to 64 MiB. The reservation was the widest declared limit across those
// same rules, which can be 1 KiB -- a 65536x under-count against a budget whose
// whole purpose is bounding resident body memory.
func TestResponseReservationCoversWhatWillActuallyBeRead(t *testing.T) {
	t.Parallel()
	noneRules := []matchedScriptRule{{Rule: ScriptRule{BodyMode: "none", MaxBodyBytes: 1024}}}

	reserved := moduleResponseBodyReservation(nil, noneRules)
	readLimit := moduleBodyReadLimit(noneRules)
	if reserved < readLimit {
		t.Fatalf("reserved %d for a read bounded at %d; the budget stops bounding what it exists to bound", reserved, readLimit)
	}

	// A declared upstream length is the honest figure and must not be inflated
	// to the global cap.
	declared := &http.Response{ContentLength: 4096}
	if got := moduleResponseBodyReservation(declared, noneRules); got != 4096 {
		t.Fatalf("declared-length reservation = %d, want 4096", got)
	}

	// The widest declared limit stays a floor: an action may synthesise a body it
	// never read, up to its own limit.
	synthesising := []matchedScriptRule{{Rule: ScriptRule{BodyMode: "text", MaxBodyBytes: 8 << 20}}}
	if got := moduleResponseBodyReservation(&http.Response{ContentLength: 16}, synthesising); got != 8<<20 {
		t.Fatalf("synthesis floor = %d, want %d", got, int64(8<<20))
	}
}

// Both bodies are resident at once when the request leg retained its buffer, so
// the response leg has to reserve on its own account. Reserving only when the
// request leg had released meant the pairing that costs the most memory was the
// one case that charged nothing for the response.
func TestResponseLegReservesEvenWhenTheRequestBufferIsStillHeld(t *testing.T) {
	t.Parallel()
	budget := newModuleBodyBudget(maxModuleBodyBudgetBytes)
	if !budget.acquire(context.Background(), maxModuleBodyBudgetBytes, moduleBodySlotWait) {
		t.Fatal("could not take the whole budget")
	}
	// With the budget fully consumed, a response-leg reservation of any size must
	// be refused rather than admitted for free.
	if budget.acquire(context.Background(), 1, moduleBodySlotWait) {
		t.Fatal("a reservation was admitted against an exhausted budget")
	}
	budget.release(maxModuleBodyBudgetBytes)
	if !budget.acquire(context.Background(), 1, moduleBodySlotWait) {
		t.Fatal("the budget did not recover after release")
	}
	budget.release(1)
}
