package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
)

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
		observed <- request.Clone(request.Context())
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write([]byte("grpc"))
		w.Header().Set("Grpc-Status", "0")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	incoming := httptest.NewRequest(http.MethodPost, "https://api.example.com/grpc", nil)
	incoming.Header.Set("Content-Type", "application/grpc")
	incoming.Header.Set("TE", "Trailers")
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
	if request.ProtoMajor != 2 || request.Header.Get("Te") != "trailers" {
		t.Fatalf("protocol=%s headers=%v", request.Proto, request.Header)
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
	transformed, err := proxy.transformModuleResponse(request, response, cfg)
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
