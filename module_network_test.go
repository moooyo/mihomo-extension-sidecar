package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeNetworkRequestUsesApprovedSOCKSOriginWithoutImplicitCredentials(t *testing.T) {
	t.Parallel()
	observed := make(chan *http.Request, 1)
	observedBody := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- request.Clone(context.Background())
		observedBody <- body
		w.Header().Add("X-Network", "one")
		w.Header().Add("X-Network", "two")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "X-Network-Final")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("accepted"))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Add("X-Network-Final", "one")
		w.Header().Add("X-Network-Final", "two")
	}))
	defer upstream.Close()

	parsedUpstream, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsedUpstream.Host)
	if err != nil {
		t.Fatal(err)
	}
	proxy, targets := startTestSOCKSTCPRelay(t, parsedUpstream.Host)
	origin := "http://network.example:" + port
	source := fmt.Sprintf(`function transform(context) {
  const reply = context.network.request({
    url: %s + "/submit?source=plugin",
    method: "POST",
    headers: {"Content-Type": "application/octet-stream", "TE": "Trailers", "X-Copied": context.request.headers.Cookie},
    body: new Uint8Array([65, 66, 67])
  })
  if (!(reply.body instanceof Uint8Array) || reply.headers["X-Network"].length !== 2) throw new Error("invalid response")
  if (reply.trailers["Grpc-Status"][0] !== "0" || reply.trailers["X-Network-Final"].length !== 2) throw new Error("invalid trailers")
  return {response: {status: reply.status, headers: reply.headers, trailers: reply.trailers, body: reply.text + ":" + reply.body[0]}}
}`, strconv.Quote(origin))
	module := nativeRuntimeModule()
	module.NetworkOrigins = []string{origin}
	rule := nativeRuntimeRule(source, "response", "text")
	rule.TimeoutMS = 2000
	request := scriptMessage{
		URL: "https://api.example.com/v1", Method: http.MethodGet,
		Headers: http.Header{"Cookie": {"session=secret"}, "Authorization": {"Bearer original"}},
	}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	cfg := Config{UpstreamProxy: proxy}
	result, err := newScriptRuntime().execute(context.Background(), cfg, nil, module, rule, request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusCreated || string(result.Body) != "accepted:97" {
		t.Fatalf("network result = %+v", result)
	}
	if values := result.Headers.Values("X-Network"); len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("round-tripped headers = %v", result.Headers)
	}
	if result.Trailers.Get("Grpc-Status") != "0" || len(result.Trailers.Values("X-Network-Final")) != 2 {
		t.Fatalf("round-tripped trailers = %v", result.Trailers)
	}
	select {
	case target := <-targets:
		if target.Host != "network.example" || strconv.Itoa(target.Port) != port {
			t.Fatalf("SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS target was not observed")
	}
	select {
	case request := <-observed:
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
			t.Fatalf("original credentials leaked: headers=%v", request.Header)
		}
		if request.Header.Get("X-Copied") != "session=secret" {
			t.Fatalf("explicitly copied data was lost: headers=%v", request.Header)
		}
		if request.Header.Get("Te") != "trailers" {
			t.Fatalf("TE trailers was not normalized: headers=%v", request.Header)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream request was not observed")
	}
	if body := <-observedBody; string(body) != "ABC" {
		t.Fatalf("upstream body = %q", body)
	}
}

func TestNativeNetworkRequestRejectsUnapprovedOriginAndLimitsCalls(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, _ := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "http://network.example:" + port

	t.Run("unapproved", func(t *testing.T) {
		source := `function transform(context) {
  try { context.network.request({url: "http://other.example:80/"}) } catch (error) {
    return {response: {body: String(error)}}
  }
  throw new Error("request unexpectedly succeeded")
}`
		module := nativeRuntimeModule()
		module.NetworkOrigins = []string{origin}
		request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
		response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
		result, err := newScriptRuntime().execute(context.Background(), Config{UpstreamProxy: proxy}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
		if err != nil || !strings.Contains(string(result.Body), "not permitted") {
			t.Fatalf("unapproved result=%q err=%v", result.Body, err)
		}
	})

	t.Run("call quota", func(t *testing.T) {
		source := fmt.Sprintf(`function transform(context) {
  let caught = ""
  for (let i = 0; i < 5; i++) {
    try { context.network.request({url: %s + "/quota"}) } catch (error) { caught = String(error) }
  }
  return {response: {body: caught}}
}`, strconv.Quote(origin))
		module := nativeRuntimeModule()
		module.NetworkOrigins = []string{origin}
		rule := nativeRuntimeRule(source, "response", "text")
		rule.TimeoutMS = 3000
		request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
		response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
		result, err := newScriptRuntime().execute(context.Background(), Config{UpstreamProxy: proxy}, nil, module, rule, request, &response)
		if err != nil || !strings.Contains(string(result.Body), "call limit exceeded") {
			t.Fatalf("quota result=%q err=%v", result.Body, err)
		}
		if calls.Load() != maxModuleNetworkCallsPerAction {
			t.Fatalf("upstream calls = %d", calls.Load())
		}
	})
}

func TestNativeNetworkRequestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var finalCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect" {
			http.Redirect(w, request, "/final", http.StatusTemporaryRedirect)
			return
		}
		finalCalls.Add(1)
		_, _ = w.Write([]byte("followed"))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, _ := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "http://network.example:" + port
	source := fmt.Sprintf(`function transform(context) {
  const reply = context.network.request({url: %s + "/redirect", method: "POST", body: "payload"})
  return {response: {status: reply.status, body: reply.text}}
}`, strconv.Quote(origin))
	module := nativeRuntimeModule()
	module.NetworkOrigins = []string{origin}
	rule := nativeRuntimeRule(source, "response", "text")
	rule.TimeoutMS = 2000
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	result, err := newScriptRuntime().execute(context.Background(), Config{UpstreamProxy: proxy}, nil, module, rule, request, &response)
	if err != nil || result.StatusCode != http.StatusTemporaryRedirect || finalCalls.Load() != 0 {
		t.Fatalf("redirect result=%+v finalCalls=%d err=%v", result, finalCalls.Load(), err)
	}
}

func TestNativeNetworkRequestVerifiesTLSThroughSOCKS(t *testing.T) {
	t.Parallel()
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
	}
	upstream.StartTLS()
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, targets := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "https://api.example.com:" + port
	options := map[string]any{"url": origin + "/secure"}
	allowed := map[string]struct{}{origin: {}}
	if _, err := performModuleNetworkRequest(context.Background(), proxy, nil, allowed, make(chan struct{}, 1), options); err == nil {
		t.Fatal("untrusted upstream certificate was accepted")
	}
	result, err := performModuleNetworkRequest(context.Background(), proxy, roots, allowed, make(chan struct{}, 1), options)
	if err != nil || result.status != http.StatusOK || string(result.body) != "secure" {
		t.Fatalf("TLS result=%+v err=%v", result, err)
	}
	select {
	case target := <-targets:
		if target.Host != "api.example.com" || strconv.Itoa(target.Port) != port {
			t.Fatalf("TLS SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS SOCKS target was not observed")
	}
}

func TestNativeNetworkRequestUsesActionAndCallerCancellation(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, _ := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "http://network.example:" + port
	source := fmt.Sprintf(`function transform(context) {
  context.network.request({url: %s + "/slow"})
  return null
}`, strconv.Quote(origin))
	module := nativeRuntimeModule()
	module.NetworkOrigins = []string{origin}
	rule := nativeRuntimeRule(source, "response", "none")
	rule.TimeoutMS = 100
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	started := time.Now()
	_, err := newScriptRuntime().execute(context.Background(), Config{UpstreamProxy: proxy}, nil, module, rule, request, &response)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("action timeout err=%v duration=%s", err, time.Since(started))
	}

	callerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	rule.TimeoutMS = 2000
	started = time.Now()
	_, err = newScriptRuntime().execute(callerCtx, Config{UpstreamProxy: proxy}, nil, module, rule, request, &response)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("caller cancellation err=%v duration=%s", err, time.Since(started))
	}
}

func TestNativeNetworkRequestInternalSizeAndConcurrencyLimits(t *testing.T) {
	t.Parallel()
	allowed := map[string]struct{}{"http://network.example": {}}
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	_, err := performModuleNetworkRequest(context.Background(), ProxyConfig{}, nil, allowed, slots, map[string]any{
		"url": "http://network.example:80/",
	})
	if err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("capacity error = %v", err)
	}
	_, err = performModuleNetworkRequest(context.Background(), ProxyConfig{}, nil, allowed, make(chan struct{}, 1), map[string]any{
		"url":  "http://network.example:80/",
		"body": strings.Repeat("x", int(maxModuleNetworkRequestBody)+1),
	})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("body limit error = %v", err)
	}
	_, err = performModuleNetworkRequest(context.Background(), ProxyConfig{}, nil, allowed, make(chan struct{}, 1), map[string]any{
		"url": "http://network.example:80/",
		"headers": map[string]any{
			"X-Oversized": strings.Repeat("x", int(maxModuleNetworkHeaderBytes)+1),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("header limit error = %v", err)
	}
	for _, headers := range []map[string]any{
		{"TE": "gzip"},
		{"Connection": "close"},
		{"X-Duplicate": "one", "x-duplicate": "two"},
	} {
		_, err = performModuleNetworkRequest(context.Background(), ProxyConfig{}, nil, allowed, make(chan struct{}, 1), map[string]any{
			"url":     "http://network.example:80/",
			"headers": headers,
		})
		if err == nil {
			t.Fatalf("unsafe network headers were accepted: %v", headers)
		}
	}
}

func TestNativeNetworkRequestRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", int(maxModuleNetworkResponseBody)+1))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, _ := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "http://network.example:" + port
	_, err := performModuleNetworkRequest(
		context.Background(), proxy, nil,
		map[string]struct{}{origin: {}}, make(chan struct{}, 1),
		map[string]any{"url": origin + "/large"},
	)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("response limit error = %v", err)
	}
}

func TestNativeNetworkRequesterReusesSameOriginAndClosesAtActionEnd(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "reused")
	}))
	defer upstream.Close()
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://reuse.example:" + port
	proxy, targets, closed := startTestSOCKSTCPRouter(t, map[string]string{
		testSOCKSTargetKey(socksTarget{Host: "reuse.example", Port: mustTestPort(t, port)}): parsed.Host,
	})
	actionCtx, cancelAction := context.WithCancel(context.Background())
	defer cancelAction()
	requester := newModuleNetworkRequester(actionCtx, proxy, nil, []string{origin}, make(chan struct{}, 1))

	for index := 0; index < 2; index++ {
		result, requestErr := requester.request(map[string]any{"url": origin + "/same-origin"})
		if requestErr != nil || result.status != http.StatusOK || string(result.body) != "reused" {
			t.Fatalf("request %d result=%+v err=%v", index, result, requestErr)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("upstream requests = %d", requests.Load())
	}
	select {
	case target := <-targets:
		if target.Host != "reuse.example" || strconv.Itoa(target.Port) != port {
			t.Fatalf("SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS connection was not observed")
	}
	select {
	case target := <-targets:
		t.Fatalf("same-origin requests opened another SOCKS connection: %+v", target)
	case <-time.After(100 * time.Millisecond):
	}

	requester.Close()
	requester.Close()
	cancelAction()
	select {
	case target := <-closed:
		if target.Host != "reuse.example" || strconv.Itoa(target.Port) != port {
			t.Fatalf("closed SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("action cleanup did not close the idle SOCKS connection")
	}

	nextActionCtx, cancelNextAction := context.WithCancel(context.Background())
	defer cancelNextAction()
	nextRequester := newModuleNetworkRequester(nextActionCtx, proxy, nil, []string{origin}, make(chan struct{}, 1))
	result, requestErr := nextRequester.request(map[string]any{"url": origin + "/next-action"})
	if requestErr != nil || string(result.body) != "reused" {
		t.Fatalf("next action result=%+v err=%v", result, requestErr)
	}
	select {
	case target := <-targets:
		if target.Host != "reuse.example" || strconv.Itoa(target.Port) != port {
			t.Fatalf("next action SOCKS target = %+v", target)
		}
	case <-time.After(time.Second):
		t.Fatal("next action reused a connection from the completed action")
	}
	nextRequester.Close()
	cancelNextAction()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("next action did not close its idle SOCKS connection")
	}
}

func TestNativeNetworkAPIClosesConnectionsWhenActionReturns(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "action")
	}))
	defer upstream.Close()
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	target := socksTarget{Host: "action.example", Port: mustTestPort(t, port)}
	origin := "http://action.example:" + port
	proxy, targets, closed := startTestSOCKSTCPRouter(t, map[string]string{
		testSOCKSTargetKey(target): parsed.Host,
	})
	source := fmt.Sprintf(`function transform(context) {
  const first = context.network.request({url: %s + "/first"})
  const second = context.network.request({url: %s + "/second"})
  return {response: {body: first.text + ":" + second.text}}
}`, strconv.Quote(origin), strconv.Quote(origin))
	module := nativeRuntimeModule()
	module.NetworkOrigins = []string{origin}
	rule := nativeRuntimeRule(source, "response", "text")
	rule.TimeoutMS = 2000
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: http.StatusOK, Headers: make(http.Header)}
	result, err := newScriptRuntime().execute(
		context.Background(), Config{UpstreamProxy: proxy}, nil, module, rule, request, &response,
	)
	if err != nil || string(result.Body) != "action:action" {
		t.Fatalf("action result=%+v err=%v", result, err)
	}
	select {
	case observed := <-targets:
		if testSOCKSTargetKey(observed) != testSOCKSTargetKey(target) {
			t.Fatalf("SOCKS target = %+v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("action SOCKS connection was not observed")
	}
	select {
	case observed := <-targets:
		t.Fatalf("action opened another same-origin SOCKS connection: %+v", observed)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case observed := <-closed:
		if testSOCKSTargetKey(observed) != testSOCKSTargetKey(target) {
			t.Fatalf("closed SOCKS target = %+v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("execute returned without closing the action network connection")
	}
}

func TestNativeNetworkRequesterKeepsExactOriginsSeparate(t *testing.T) {
	t.Parallel()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "second")
	}))
	defer second.Close()
	firstURL, err := url.Parse(first.URL)
	if err != nil {
		t.Fatal(err)
	}
	secondURL, err := url.Parse(second.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, firstPort, err := net.SplitHostPort(firstURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPort, err := net.SplitHostPort(secondURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	firstTarget := socksTarget{Host: "first.example", Port: mustTestPort(t, firstPort)}
	secondTarget := socksTarget{Host: "second.example", Port: mustTestPort(t, secondPort)}
	firstOrigin := "http://first.example:" + firstPort
	secondOrigin := "http://second.example:" + secondPort
	proxy, targets, closed := startTestSOCKSTCPRouter(t, map[string]string{
		testSOCKSTargetKey(firstTarget):  firstURL.Host,
		testSOCKSTargetKey(secondTarget): secondURL.Host,
	})
	actionCtx, cancelAction := context.WithCancel(context.Background())
	defer cancelAction()
	requester := newModuleNetworkRequester(
		actionCtx, proxy, nil, []string{firstOrigin, secondOrigin}, make(chan struct{}, 1),
	)

	for _, test := range []struct {
		origin string
		body   string
	}{
		{origin: firstOrigin, body: "first"},
		{origin: secondOrigin, body: "second"},
		{origin: firstOrigin, body: "first"},
		{origin: secondOrigin, body: "second"},
	} {
		result, requestErr := requester.request(map[string]any{"url": test.origin + "/isolated"})
		if requestErr != nil || string(result.body) != test.body {
			t.Fatalf("origin %s result=%+v err=%v", test.origin, result, requestErr)
		}
	}

	observed := make(map[string]int)
	for index := 0; index < 2; index++ {
		select {
		case target := <-targets:
			observed[testSOCKSTargetKey(target)]++
		case <-time.After(time.Second):
			t.Fatal("expected per-origin SOCKS connections were not observed")
		}
	}
	if observed[testSOCKSTargetKey(firstTarget)] != 1 || observed[testSOCKSTargetKey(secondTarget)] != 1 {
		t.Fatalf("SOCKS connections by origin = %v", observed)
	}
	select {
	case target := <-targets:
		t.Fatalf("exact-origin transports opened an unexpected connection: %+v", target)
	case <-time.After(100 * time.Millisecond):
	}

	requester.Close()
	cancelAction()
	for index := 0; index < 2; index++ {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("action cleanup did not close every exact-origin connection")
		}
	}
}

func startTestSOCKSTCPRelay(t *testing.T, upstreamAddress string) (ProxyConfig, <-chan socksTarget) {
	t.Helper()
	username := "network-relay-user"
	password := "network-relay-password-1234"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	targets := make(chan socksTarget, 32)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveTestSOCKSTCPRelayConnection(conn, upstreamAddress, username, password, targets)
		}
	}()
	return ProxyConfig{Address: listener.Addr().String(), Username: username, Password: password}, targets
}

func startTestSOCKSTCPRouter(t *testing.T, routes map[string]string) (ProxyConfig, <-chan socksTarget, <-chan socksTarget) {
	t.Helper()
	username := "network-router-user"
	password := "network-router-password-1234"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	targets := make(chan socksTarget, 32)
	closed := make(chan socksTarget, 32)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveTestSOCKSTCPRouterConnection(conn, routes, username, password, targets, closed)
		}
	}()
	return ProxyConfig{Address: listener.Addr().String(), Username: username, Password: password}, targets, closed
}

func serveTestSOCKSTCPRouterConnection(
	conn net.Conn,
	routes map[string]string,
	username string,
	password string,
	targets chan<- socksTarget,
	closed chan<- socksTarget,
) {
	defer conn.Close()
	command, target, err := readSOCKSRequest(conn, username, password)
	if err != nil || command != socksCommandConnect {
		return
	}
	targets <- target
	defer func() { closed <- target }()
	upstreamAddress, permitted := routes[testSOCKSTargetKey(target)]
	if !permitted {
		_ = writeSOCKSReply(conn, 2, nil)
		return
	}
	upstream, err := net.Dial("tcp4", upstreamAddress)
	if err != nil {
		_ = writeSOCKSReply(conn, 1, nil)
		return
	}
	defer upstream.Close()
	if err := writeSOCKSReply(conn, 0, upstream.LocalAddr()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

func testSOCKSTargetKey(target socksTarget) string {
	return net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
}

func mustTestPort(t *testing.T, value string) int {
	t.Helper()
	port, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func serveTestSOCKSTCPRelayConnection(conn net.Conn, upstreamAddress, username, password string, targets chan<- socksTarget) {
	defer conn.Close()
	command, target, err := readSOCKSRequest(conn, username, password)
	if err != nil || command != socksCommandConnect {
		return
	}
	select {
	case targets <- target:
	default:
	}
	upstream, err := net.Dial("tcp4", upstreamAddress)
	if err != nil {
		_ = writeSOCKSReply(conn, 1, nil)
		return
	}
	defer upstream.Close()
	if err := writeSOCKSReply(conn, 0, upstream.LocalAddr()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}
