package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP3ConnectionCapacityIsProxyWide(t *testing.T) {
	proxy := &interceptProxy{}
	first := newUpstreamTransportGeneration(Config{generation: 1})
	second := newUpstreamTransportGeneration(Config{generation: 2})
	first.refs = 2
	second.refs = 2

	var slots chan struct{}
	for index := 0; index < maxUpstreamHTTP3Connections; index++ {
		generation := first
		if index%2 == 1 {
			generation = second
		}
		acquired, err := proxy.acquireHTTP3ConnectionSlot(context.Background(), generation)
		if err != nil {
			t.Fatalf("acquire slot %d: %v", index, err)
		}
		if slots == nil {
			slots = acquired
		} else if acquired != slots {
			t.Fatal("HTTP/3 generations do not share one proxy-wide semaphore")
		}
	}
	if cap(slots) != maxUpstreamHTTP3Connections || len(slots) != maxUpstreamHTTP3Connections {
		t.Fatalf("HTTP/3 capacity len=%d cap=%d", len(slots), cap(slots))
	}
	if _, err := proxy.acquireHTTP3ConnectionSlot(context.Background(), first); err == nil {
		t.Fatal("proxy-wide HTTP/3 capacity allowed a connection above the limit")
	}

	<-slots
	reacquired, err := proxy.acquireHTTP3ConnectionSlot(context.Background(), second)
	if err != nil {
		t.Fatalf("released HTTP/3 capacity was not reusable: %v", err)
	}
	if reacquired != slots || len(slots) != maxUpstreamHTTP3Connections {
		t.Fatal("released HTTP/3 capacity was not returned to the shared semaphore")
	}
	for index := 0; index < maxUpstreamHTTP3Connections; index++ {
		<-slots
	}
}

func TestUpstreamHTTP2GenerationRetiresIdleConnectionsWithoutInterruptingInFlightBody(t *testing.T) {
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	oldHeaders := make(chan struct{})
	releaseOldBody := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/old":
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			close(oldHeaders)
			<-releaseOldBody
			_, _ = io.WriteString(w, "old-finished")
		case "/new":
			_, _ = io.WriteString(w, "new-generation")
		default:
			http.NotFound(w, request)
		}
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
	}
	upstream.StartTLS()
	defer upstream.Close()

	target := socksTarget{Host: "api.example.com", Port: 443}
	proxyConfig, targets, closed := startTestSOCKSTCPRouter(t, map[string]string{
		testSOCKSTargetKey(target): upstream.Listener.Addr().String(),
	})
	module := nativeRuntimeModule()
	module.Enabled = true
	cfg := Config{
		generation:     1,
		MITM:           MITMSettings{Enabled: true, HTTP2: true},
		UpstreamProxy:  proxyConfig,
		Modules:        []Module{module},
		ExecutionOrder: []string{module.ID},
	}
	proxy := &interceptProxy{upstreamRoots: roots}
	defer proxy.closeUpstreamTransports()

	type result struct {
		body string
		err  error
	}
	oldResult := make(chan result, 1)
	go func() {
		request, err := http.NewRequest(http.MethodGet, "https://api.example.com/old", nil)
		if err != nil {
			oldResult <- result{err: err}
			return
		}
		response, cleanup, err := proxy.roundTrip(request, cfg)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			oldResult <- result{err: err}
			return
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(response.Body)
		oldResult <- result{body: string(body), err: readErr}
	}()

	select {
	case <-oldHeaders:
	case <-time.After(3 * time.Second):
		t.Fatal("old generation did not publish response headers")
	}
	waitForSOCKSTarget(t, targets, target)

	newCfg := cfg
	newCfg.generation = 2
	newBody := doTestProxyRoundTripPath(t, proxy, newCfg, "/new")
	if newBody != "new-generation" {
		t.Fatalf("new generation body = %q", newBody)
	}
	waitForSOCKSTarget(t, targets, target)
	select {
	case completed := <-oldResult:
		t.Fatalf("old generation was interrupted before release: %+v", completed)
	default:
	}

	close(releaseOldBody)
	select {
	case completed := <-oldResult:
		if completed.err != nil || completed.body != "old-finished" {
			t.Fatalf("old generation result = %+v", completed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old generation did not finish after its body was released")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("retired old-generation SOCKS connection was not closed")
	}

	if body := doTestProxyRoundTripPath(t, proxy, newCfg, "/new"); body != "new-generation" {
		t.Fatalf("reused new generation body = %q", body)
	}
	assertNoSOCKSTarget(t, targets)

	revokedModule := nativeRuntimeModule()
	revokedModule.Enabled = true
	revokedModule.CaptureHosts = []string{"other.example.com"}
	revokedCfg := newCfg
	revokedCfg.generation = 3
	revokedCfg.Modules = []Module{revokedModule}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.com/revoked", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, cleanup, err := proxy.roundTrip(request, revokedCfg)
	if cleanup != nil {
		cleanup()
	}
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("new generation reused an older connection after host permission was revoked")
	}
	assertNoSOCKSTarget(t, targets)
}

func TestUpstreamHTTP2TransportReusesConnectionsAndDoesNotRollBackGeneration(t *testing.T) {
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	protocols := make(chan int, 8)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		protocols <- request.ProtoMajor
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
	}
	upstream.StartTLS()
	defer upstream.Close()

	proxyConfig, targets := startTestSOCKSTCPRelay(t, upstream.Listener.Addr().String())
	module := nativeRuntimeModule()
	module.Enabled = true
	cfg := Config{
		generation:     1,
		MITM:           MITMSettings{Enabled: true, HTTP2: true},
		UpstreamProxy:  proxyConfig,
		Modules:        []Module{module},
		ExecutionOrder: []string{module.ID},
	}
	proxy := &interceptProxy{upstreamRoots: roots}
	defer proxy.closeUpstreamTransports()

	doTestProxyRoundTrip(t, proxy, cfg)
	doTestProxyRoundTrip(t, proxy, cfg)
	if got := len(targets); got != 1 {
		t.Fatalf("same generation opened %d SOCKS connections, want 1", got)
	}

	newCfg := cfg
	newCfg.generation = 2
	doTestProxyRoundTrip(t, proxy, newCfg)
	if got := len(targets); got != 2 {
		t.Fatalf("new generation opened %d total SOCKS connections, want 2", got)
	}

	// A request that arrives late with an older immutable snapshot must use a
	// one-shot transport and must not replace the active generation.
	doTestProxyRoundTrip(t, proxy, cfg)
	doTestProxyRoundTrip(t, proxy, newCfg)
	if got := len(targets); got != 3 {
		t.Fatalf("late old generation changed connection reuse: connections=%d want=3", got)
	}
	proxy.transportMu.Lock()
	activeGeneration := proxy.upstream.generation
	proxy.transportMu.Unlock()
	if activeGeneration != newCfg.generation {
		t.Fatalf("active generation rolled back to %d", activeGeneration)
	}

	zeroGeneration := newCfg
	zeroGeneration.generation = 0
	doTestProxyRoundTrip(t, proxy, zeroGeneration)
	doTestProxyRoundTrip(t, proxy, zeroGeneration)
	doTestProxyRoundTrip(t, proxy, newCfg)
	if got := len(targets); got != 5 {
		t.Fatalf("generation zero was shared or replaced the active pool: connections=%d want=5", got)
	}

	if got := len(protocols); got != 8 {
		t.Fatalf("upstream handled %d requests, want 8", got)
	}
	for range 8 {
		protocol := <-protocols
		if protocol != 2 {
			t.Fatalf("upstream protocol major=%d, want HTTP/2", protocol)
		}
	}
}

func doTestProxyRoundTrip(t *testing.T, proxy *interceptProxy, cfg Config) {
	t.Helper()
	_ = doTestProxyRoundTripPath(t, proxy, cfg, "/resource")
}

func doTestProxyRoundTripPath(t *testing.T, proxy *interceptProxy, cfg Config, path string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://api.example.com"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, cleanup, err := proxy.roundTrip(request, cfg)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		response.Body.Close()
		cleanup()
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		cleanup()
		t.Fatal(err)
	}
	cleanup()
	return string(body)
}

func waitForSOCKSTarget(t *testing.T, targets <-chan socksTarget, want socksTarget) {
	t.Helper()
	select {
	case got := <-targets:
		if got != want {
			t.Fatalf("SOCKS target = %+v, want %+v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("SOCKS target %+v was not observed", want)
	}
}

func assertNoSOCKSTarget(t *testing.T, targets <-chan socksTarget) {
	t.Helper()
	select {
	case got := <-targets:
		t.Fatalf("unexpected SOCKS connection to %+v", got)
	case <-time.After(150 * time.Millisecond):
	}
}

// dialSOCKS5TCP bounds its connect but not the SOCKS exchange that follows, and
// no transport timeout starts until the dial returns. Production calls it with
// no deadline above it, so a mihomo that accepts the connection and never speaks
// SOCKS pinned the dial, its handler goroutine and the connection forever.
func TestUpstreamDialBoundsTheSOCKSHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out upstreamHandshakeTimeout")
	}
	t.Parallel()
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			// Accept and say nothing, ever.
			defer conn.Close()
		}
	}()

	module := Module{ID: "io.example.fixture", Enabled: true, CaptureHosts: []string{"api.example.com"}}
	cfg := Config{
		MITM:          MITMSettings{Enabled: true},
		UpstreamProxy: ProxyConfig{Address: silent.Addr().String(), Username: "upstream-user-1234", Password: "upstream-password-1234567"},
		Modules:       []Module{module}, ExecutionOrder: []string{module.ID},
	}
	transport := (&interceptProxy{}).newHTTPTransportForProjection(newUpstreamTransportProjection(cfg))
	defer transport.CloseIdleConnections()

	started := time.Now()
	// context.Background is the production condition: nothing above the dial
	// carries a deadline.
	conn, err := transport.DialContext(context.Background(), "tcp", "api.example.com:443")
	elapsed := time.Since(started)
	if err == nil {
		conn.Close()
		t.Fatal("a silent SOCKS peer completed a handshake")
	}
	if elapsed > upstreamHandshakeTimeout+5*time.Second {
		t.Fatalf("stalled SOCKS handshake took %s, want about %s", elapsed, upstreamHandshakeTimeout)
	}
	t.Logf("stalled SOCKS handshake cut after %s: %v", elapsed.Round(time.Millisecond), err)
}

// acquireBodySlot used to be a bare select/default: the first request to find
// the pool full was refused outright, even though reservations routinely clear
// in milliseconds. acquireHTTP3ConnectionSlot, the other capacity limit in this
// file, already waits with a timer and a ctx.Done. This one now matches it.
func TestAcquireBodySlotWaitsForABurstToClear(t *testing.T) {
	t.Parallel()
	proxy := &interceptProxy{bodySlots: make(chan struct{}, 2)}
	proxy.bodySlots <- struct{}{}
	proxy.bodySlots <- struct{}{}

	go func() {
		time.Sleep(30 * time.Millisecond)
		proxy.releaseBodySlot()
	}()
	started := time.Now()
	if !proxy.acquireBodySlot(context.Background()) {
		t.Fatal("a slot that freed well inside the wait window was still refused")
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("acquired after %s without waiting", elapsed)
	}

	// A pool that stays full still refuses, and bounded: the reservation is held
	// for the whole request, so waiting longer would only pin this connection
	// behind a shortage it cannot outlast.
	started = time.Now()
	if proxy.acquireBodySlot(context.Background()) {
		t.Fatal("a full pool admitted a third reservation")
	}
	if elapsed := time.Since(started); elapsed > moduleBodySlotWait*4 {
		t.Fatalf("refusal took %s, want about %s", elapsed, moduleBodySlotWait)
	}

	// A client that goes away stops waiting immediately.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	started = time.Now()
	if proxy.acquireBodySlot(canceled) {
		t.Fatal("a canceled request took a reservation")
	}
	if elapsed := time.Since(started); elapsed > moduleBodySlotWait/2 {
		t.Fatalf("a canceled request waited %s", elapsed)
	}
}
