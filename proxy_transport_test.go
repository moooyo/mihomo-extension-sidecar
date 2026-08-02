package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// staticCertificateStore writes a config pointing at the given key pair so a
// certificateStore can be built without standing up the whole proxy.
func staticCertificateStore(t *testing.T, certPath, keyPath string) *configStore {
	t.Helper()
	cfg := validNativeConfig()
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// The client-facing leg must resume across connections.
//
// A server's session ticket keys belong to its tls.Config, and this proxy built
// a fresh one per connection, so a ticket issued on one connection could never
// be decrypted on the next: every connection paid a full handshake and a
// signature. Measured against the same certificate, a fresh config per
// connection resumes on no connection, and a clone carrying shared keys resumes
// from the second on.
//
// The clone matters for a second reason the test cannot see: ServeTLS hands its
// TLSConfig to http2ConfigureServer, which writes to it, and this proxy builds
// one http.Server per connection.
func TestClientFacingTLSResumesAcrossConnections(t *testing.T) {
	t.Parallel()
	certPath, keyPath, pool := writeTestInterceptCertificate(t)
	store, err := newCertificateStore(staticCertificateStore(t, certPath, keyPath))
	if err != nil {
		t.Fatal(err)
	}
	proxy := &interceptProxy{certificates: store, tlsErrors: newTLSHandshakeErrorReporter()}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			raw, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(raw net.Conn) {
				config, configErr := proxy.mitmTLSConfig(false)
				if configErr != nil {
					_ = raw.Close()
					return
				}
				server := tls.Server(raw, config)
				if server.Handshake() != nil {
					_ = server.Close()
					return
				}
				_, _ = server.Write([]byte("ok"))
				_, _ = server.Read(make([]byte, 1))
				_ = server.Close()
			}(raw)
		}
	}()

	cache := tls.NewLRUClientSessionCache(8)
	dial := func() bool {
		conn, dialErr := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			RootCAs: pool, ServerName: "api.example.com", ClientSessionCache: cache,
		})
		if dialErr != nil {
			t.Fatalf("dial: %v", dialErr)
		}
		resumed := conn.ConnectionState().DidResume
		_, _ = io.ReadFull(conn, make([]byte, 2))
		_, _ = conn.Write([]byte("x"))
		_ = conn.Close()
		return resumed
	}

	if dial() {
		t.Fatal("the first connection reported a resumption with nothing to resume")
	}
	if !dial() {
		t.Fatal("the second connection did not resume; the leg is issuing tickets no later connection can read")
	}
	if !dial() {
		t.Fatal("the third connection did not resume")
	}
}

// A rotation must not strand a ticket issued a moment before it.
func TestSessionTicketKeysRotateKeepingThePrevious(t *testing.T) {
	t.Parallel()
	moment := time.Now()
	proxy := &interceptProxy{tlsNow: func() time.Time { return moment }}

	first, err := proxy.sessionTicketKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("first call returned %d keys, want 1", len(first))
	}
	again, err := proxy.sessionTicketKeys()
	if err != nil {
		t.Fatal(err)
	}
	if again[0] != first[0] {
		t.Fatal("the key rotated inside its own lifetime")
	}

	moment = moment.Add(mitmTicketKeyLifetime + time.Minute)
	rotated, err := proxy.sessionTicketKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 2 {
		t.Fatalf("a rotation returned %d keys, want the new one and the previous", len(rotated))
	}
	if rotated[0] == first[0] {
		t.Fatal("the rotation reissued the same key")
	}
	if rotated[1] != first[0] {
		t.Fatal("the rotation dropped the previous key, stranding tickets issued under it")
	}

	moment = moment.Add(mitmTicketKeyLifetime + time.Minute)
	third, err := proxy.sessionTicketKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != mitmTicketKeyHistory {
		t.Fatalf("history grew to %d keys, want at most %d", len(third), mitmTicketKeyHistory)
	}
	if third[1] != rotated[0] {
		t.Fatal("the second rotation kept the wrong previous key")
	}
}

// A QUIC keepalive shorter than the idle timeout makes the idle timeout dead
// code: the connection is never idle, so it never closes, so the slot the dial
// took is never released and the 64-connection budget only ever shrinks. Both
// settings arrived in the same commit and cancelled each other out.
//
// The reclaim path is the whole reason this matters -- Dial takes a slot and
// only connection.Context().Done() gives it back.
func TestQUICIdleTimeoutIsNotDefeatedByAKeepalive(t *testing.T) {
	t.Parallel()
	proxy := &interceptProxy{}
	generation := &upstreamTransportGeneration{}
	transport := proxy.newHTTP3Transport(generation, quic.Version1)

	if transport.QUICConfig.KeepAlivePeriod != 0 {
		t.Fatalf("upstream keepalive = %v; a keepalive here means the idle timeout never fires and the connection slot never returns",
			transport.QUICConfig.KeepAlivePeriod)
	}
	if transport.QUICConfig.MaxIdleTimeout != upstreamHTTPIdleTimeout {
		t.Fatalf("upstream MaxIdleTimeout = %v, want %v so HTTP/3 reclaims on the same clock as the HTTP/1 and HTTP/2 pool",
			transport.QUICConfig.MaxIdleTimeout, upstreamHTTPIdleTimeout)
	}
}

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

// A commit that changes nothing the upstream leg depends on must keep its warm
// connections.
//
// The generation number advances on any content change, and almost none of them
// reach this leg: a setting, an enable toggle, a script body, a match pattern
// all leave the proxy, the protocol and the target authorization exactly as they
// were. Retiring on the number meant every commit dropped every pooled
// connection and every TLS session with it, and paid a fresh SOCKS handshake
// plus a fresh origin handshake on the next request.
func TestUpstreamGenerationSurvivesACommitTheTransportDoesNotCareAbout(t *testing.T) {
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "served")
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
	}
	upstream.StartTLS()
	defer upstream.Close()

	target := socksTarget{Host: "api.example.com", Port: 443}
	proxyConfig, targets, _ := startTestSOCKSTCPRouter(t, map[string]string{
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

	if body := doTestProxyRoundTripPath(t, proxy, cfg, "/first"); body != "served" {
		t.Fatalf("first body = %q", body)
	}
	waitForSOCKSTarget(t, targets, target)
	first := proxy.upstream

	// A commit that touches only what the script runtime cares about. None of it
	// reaches the upstream leg.
	settled := cfg
	settled.generation = 2
	changed := module
	changed.Description = "an edited description"
	changed.PersistentStorage = !module.PersistentStorage
	settled.Modules = []Module{changed}

	if body := doTestProxyRoundTripPath(t, proxy, settled, "/second"); body != "served" {
		t.Fatalf("second body = %q", body)
	}
	assertNoSOCKSTarget(t, targets)
	if proxy.upstream != first {
		t.Fatal("the pool was replaced by a commit the transport does not depend on")
	}
	if proxy.upstream.generation != settled.generation {
		t.Fatalf("the surviving pool kept generation %d, want the newer %d so the comparison keeps moving forward",
			proxy.upstream.generation, settled.generation)
	}

	// And a commit that does reach it still retires the pool.
	retiring := settled
	retiring.generation = 3
	widened := changed
	widened.CaptureHosts = append(append([]string(nil), module.CaptureHosts...), "extra.example.com")
	retiring.Modules = []Module{widened}
	if body := doTestProxyRoundTripPath(t, proxy, retiring, "/third"); body != "served" {
		t.Fatalf("third body = %q", body)
	}
	waitForSOCKSTarget(t, targets, target)
	if proxy.upstream == first {
		t.Fatal("a changed target authorization did not retire the pool")
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
	// Retirement follows the transport fingerprint now, not the generation
	// number, so this has to move something the upstream leg actually depends
	// on. An added capture host does that without changing whether
	// api.example.com is authorized.
	retiring := module
	retiring.CaptureHosts = append(append([]string(nil), module.CaptureHosts...), "extra.example.com")
	newCfg.Modules = []Module{retiring}
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
	// Retirement follows the transport fingerprint, so a bare generation bump
	// would now reuse the pool -- which is what
	// TestUpstreamGenerationSurvivesACommitTheTransportDoesNotCareAbout covers.
	// This case is about a commit that does reach the upstream leg.
	widened := module
	widened.CaptureHosts = append(append([]string(nil), module.CaptureHosts...), "extra.example.com")
	newCfg.Modules = []Module{widened}
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
	proxy := &interceptProxy{bodyBudget: newModuleBodyBudget(maxModuleBodyBudgetBytes)}
	proxy.bodyBudget.acquire(context.Background(), maxModuleBodyBudgetBytes, time.Second)

	go func() {
		time.Sleep(30 * time.Millisecond)
		proxy.releaseBodySlot(maxModuleBodyBudgetBytes)
	}()
	started := time.Now()
	if !proxy.acquireBodySlot(context.Background(), maxModuleBodyBudgetBytes) {
		t.Fatal("a slot that freed well inside the wait window was still refused")
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("acquired after %s without waiting", elapsed)
	}

	// A pool that stays full still refuses, and bounded: the reservation is held
	// for the whole request, so waiting longer would only pin this connection
	// behind a shortage it cannot outlast.
	started = time.Now()
	if proxy.acquireBodySlot(context.Background(), maxModuleBodyBudgetBytes) {
		t.Fatal("a full pool admitted a third reservation")
	}
	if elapsed := time.Since(started); elapsed > moduleBodySlotWait*4 {
		t.Fatalf("refusal took %s, want about %s", elapsed, moduleBodySlotWait)
	}

	// A client that goes away stops waiting immediately.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	started = time.Now()
	if proxy.acquireBodySlot(canceled, maxModuleBodyBudgetBytes) {
		t.Fatal("a canceled request took a reservation")
	}
	if elapsed := time.Since(started); elapsed > moduleBodySlotWait/2 {
		t.Fatalf("a canceled request waited %s", elapsed)
	}
}
