package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// nativeAsyncFixture serves a TLS origin behind the same SOCKS relay the runtime
// uses in production and returns the module wiring a native script sees.
func nativeAsyncFixture(t *testing.T, handler http.HandlerFunc) (Module, string, Config, *x509.CertPool) {
	t.Helper()
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	parsed, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	proxy, _ := startTestSOCKSTCPRelay(t, parsed.Host)
	origin := "https://api.example.com:" + port
	module := nativeRuntimeModule()
	module.Network = true
	return module, origin, Config{UpstreamProxy: proxy}, roots
}

func runNativeAsyncScript(t *testing.T, source string, module Module, cfg Config, roots *x509.CertPool, timeoutMS int) (scriptResult, error) {
	t.Helper()
	rule := nativeRuntimeRule(source, "response", "text")
	if timeoutMS > 0 {
		rule.TimeoutMS = timeoutMS
	}
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	return newScriptRuntime().execute(context.Background(), cfg, roots, module, rule, request, &response)
}

func TestNativeAsyncNetworkRunsRequestsConcurrently(t *testing.T) {
	t.Parallel()
	// The synchronous form holds the VM for a whole round trip, so two lookups
	// cost both latencies. This is the divergence the async form exists to
	// close, and serialization is visible in wall-clock time.
	var inFlight, peak int64
	module, origin, cfg, roots := nativeAsyncFixture(t, func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&inFlight, 1)
		for {
			seen := atomic.LoadInt64(&peak)
			if current <= seen || atomic.CompareAndSwapInt64(&peak, seen, current) {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		_, _ = w.Write([]byte(strings.TrimPrefix(r.URL.Path, "/")))
	})
	source := `async function transform(context) {
  const [first, second] = await Promise.all([
    context.network.requestAsync({url: "` + origin + `/alpha"}),
    context.network.requestAsync({url: "` + origin + `/beta"}),
  ])
  return { response: { body: first.text + "," + second.text + "," + first.status } }
}`
	started := time.Now()
	result, err := runNativeAsyncScript(t, source, module, cfg, roots, 20000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "alpha,beta,200" {
		t.Fatalf("body = %q, want both responses", got)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency = %d, want the two requests to overlap", peak)
	}
	if elapsed := time.Since(started); elapsed > 450*time.Millisecond {
		t.Fatalf("two 250ms requests took %s, which means they serialized", elapsed)
	}
}

func TestNativeAsyncNetworkRejectsInsteadOfThrowing(t *testing.T) {
	t.Parallel()
	// A rejection lets `await` inside try/catch read the way the synchronous
	// form does. Throwing synchronously out of the call would escape the
	// script's own error handling instead.
	module, _, cfg, roots := nativeAsyncFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("unused"))
	})
	source := `async function transform(context) {
  try {
    await context.network.requestAsync({url: "https://127.0.0.1/v1"})
    return { response: { body: "unexpected-success" } }
  } catch (error) {
    return { response: { body: "rejected:" + (String(error).includes("host") ? "host" : "other") } }
  }
}`
	result, err := runNativeAsyncScript(t, source, module, cfg, roots, 10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "rejected:host" {
		t.Fatalf("body = %q, want the refused host delivered as a rejection", got)
	}
}

func TestNativeAsyncNetworkSharesThePerActionBudget(t *testing.T) {
	t.Parallel()
	// Counting the two entry points separately would let a script double its
	// allowance simply by mixing them.
	module, origin, cfg, roots := nativeAsyncFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	source := `async function transform(context) {
  let spent = 0
  try {
    for (let index = 0; index < ` + strconv.Itoa(maxModuleNetworkCallsPerAction) + `; index++) {
      context.network.request({url: "` + origin + `/sync" + index})
      spent++
    }
    await context.network.requestAsync({url: "` + origin + `/async"})
    return { response: { body: "budget-not-shared:" + spent } }
  } catch (error) {
    return { response: { body: "shared:" + spent + ":" + (String(error).includes("call limit") ? "limit" : "other") } }
  }
}`
	result, err := runNativeAsyncScript(t, source, module, cfg, roots, 20000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "shared:"+strconv.Itoa(maxModuleNetworkCallsPerAction)+":limit" {
		t.Fatalf("body = %q, want the async call refused by the shared budget", got)
	}
}

func TestNativeAsyncNetworkIsAbsentWithoutTheGrant(t *testing.T) {
	t.Parallel()
	// Without a network permission neither entry point exists, so a script
	// takes its own no-network branch rather than calling into a stub.
	source := `function transform(context) {
  return { response: { body: String(context.network) } }
}`
	result, err := asyncRuntimeCall(t, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "undefined" {
		t.Fatalf("context.network = %q without a grant, want it undefined", got)
	}
}

func TestNativeSynchronousNetworkStillWorks(t *testing.T) {
	t.Parallel()
	// The existing entry point keeps its exact behavior: adding the async form
	// must not change what an already-reviewed extension does.
	module, origin, cfg, roots := nativeAsyncFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("sync-body"))
	})
	source := `function transform(context) {
  const result = context.network.request({url: "` + origin + `/v1"})
  return { response: { body: result.text + ":" + result.status } }
}`
	result, err := runNativeAsyncScript(t, source, module, cfg, roots, 15000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "sync-body:200" {
		t.Fatalf("body = %q, want the synchronous result unchanged", got)
	}
}

func TestNativeAsyncNetworkEndsWithTheActionDeadline(t *testing.T) {
	t.Parallel()
	module, origin, cfg, roots := nativeAsyncFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(3 * time.Second)
		_, _ = w.Write([]byte("late"))
	})
	source := `async function transform(context) {
  await context.network.requestAsync({url: "` + origin + `/slow"})
  return { response: { body: "unreachable" } }
}`
	started := time.Now()
	if _, err := runNativeAsyncScript(t, source, module, cfg, roots, 300); err == nil {
		t.Fatal("expected the action deadline to end a pending async request")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("action took %s, want it bounded by the deadline", elapsed)
	}
}
