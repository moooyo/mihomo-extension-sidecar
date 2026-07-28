package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// runCompatHTTPScript wires the real network requester into a compat VM and
// drives the script to $done. It exercises the path a published bundle takes
// when a provider is selected: the blocking request runs on a worker goroutine
// and its completion is posted back to the goroutine that owns the VM.
func runCompatHTTPScript(t *testing.T, source string, requester *moduleNetworkRequester) (goja.Value, error) {
	t.Helper()
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	if err := loop.installTimerAPI(vm); err != nil {
		t.Fatal(err)
	}
	if err := installWebAPI(vm); err != nil {
		t.Fatal(err)
	}
	options := compatFixtureOptions()
	options.requester = requester
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(source); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := loop.wait(ctx, entry.settled); err != nil {
		return nil, err
	}
	return entry.result, nil
}

// compatHTTPFixture starts a TLS provider behind the same SOCKS relay the
// runtime uses in production, and returns a requester holding the unrestricted
// grant a provider-backed extension is enabled with.
func compatHTTPFixture(t *testing.T, handler http.HandlerFunc) (*moduleNetworkRequester, string) {
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
	requester := newModuleNetworkRequester(context.Background(), proxy, roots, nil, make(chan struct{}, 4))
	requester.allowAny = true
	t.Cleanup(requester.Close)
	return requester, "https://api.example.com:" + port
}

func TestCompatHTTPClientDeliversTheCallbackShape(t *testing.T) {
	t.Parallel()
	// $httpClient hands the callback (error, response, body). The bundles reject on a
	// truthy first argument and otherwise read response.status and the body as
	// the third argument, so all three positions have to be right.
	requester, origin := compatHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	source := `$httpClient.get({url: "` + origin + `/v1/data"}, (error, response, body) => {
  $done({ body: JSON.stringify({
    error: String(error),
    status: response.status,
    method: response.headers["X-Echo-Method"],
    payload: body,
    bodyType: typeof body,
  }) })
})`
	result, err := runCompatHTTPScript(t, source, requester)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	body, _ := exported["body"].(string)
	for _, want := range []string{`"error":"null"`, `"status":200`, `"method":"GET"`, `"payload":"{\"ok\":true}"`, `"bodyType":"string"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("callback delivered %s, want it to contain %s", body, want)
		}
	}
}

func TestCompatHTTPClientPostsAMethodAndBody(t *testing.T) {
	t.Parallel()
	received := make(chan string, 1)
	requester, origin := compatHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		payload := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(payload)
		received <- r.Method + " " + r.Header.Get("X-Token") + " " + string(payload)
		_, _ = w.Write([]byte("stored"))
	})
	source := `$httpClient.post({
  url: "` + origin + `/v1/push",
  headers: {"X-Token": "secret"},
  body: "payload",
}, (error, response, body) => $done({ body: body }))`
	result, err := runCompatHTTPScript(t, source, requester)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	if exported["body"] != "stored" {
		t.Fatalf("body = %v, want stored", exported["body"])
	}
	select {
	case got := <-received:
		if got != "POST secret payload" {
			t.Fatalf("upstream saw %q, want the method, header, and body forwarded", got)
		}
	default:
		t.Fatal("upstream never received the request")
	}
}

func TestCompatHTTPClientBinaryModeReturnsBytes(t *testing.T) {
	t.Parallel()
	// The bundles set binary-mode for a FlatBuffer payload and then read the
	// body as bytes. Handing them a string would corrupt it at the first
	// non-UTF-8 byte.
	requester, origin := compatHTTPFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte{0x00, 0xff, 0x10, 0x80})
	})
	source := `$httpClient.get({url: "` + origin + `/v1/blob", "binary-mode": true}, (error, response, body) => {
  $done({ body: JSON.stringify({ kind: body?.constructor?.name, length: body?.length, first: body?.[1] }) })
})`
	result, err := runCompatHTTPScript(t, source, requester)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	body, _ := exported["body"].(string)
	if !strings.Contains(body, `"kind":"Uint8Array"`) || !strings.Contains(body, `"length":4`) || !strings.Contains(body, `"first":255`) {
		t.Fatalf("binary body projected as %s", body)
	}
}

func TestCompatHTTPClientReportsATransportFailureToTheCallback(t *testing.T) {
	t.Parallel()
	// A failure has to arrive as a truthy first argument, because that is the
	// only branch the bundles treat as a rejection. Throwing instead would
	// escape into their catch and look like a bundle that declined to act.
	requester, _ := compatHTTPFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("unused"))
	})
	source := `$httpClient.get({url: "https://unreachable.invalid/v1"}, (error, response, body) => {
  $done({ body: JSON.stringify({ failed: Boolean(error), hasResponse: response !== undefined }) })
})`
	result, err := runCompatHTTPScript(t, source, requester)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	body, _ := exported["body"].(string)
	if !strings.Contains(body, `"failed":true`) {
		t.Fatalf("transport failure reported as %s", body)
	}
}

func TestCompatHTTPClientIsAbsentWithoutTheNetworkGrant(t *testing.T) {
	t.Parallel()
	// Without a network permission the global must not exist at all, so a
	// bundle takes its own no-network branch rather than calling into a stub.
	result, err := runCompatScript(t, `$done({ body: typeof globalThis.$httpClient })`, compatFixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	if exported["body"] != "undefined" {
		t.Fatalf("$httpClient = %v without a grant, want it undefined", exported["body"])
	}
}

func TestCompatHTTPClientEnforcesThePerActionCallBudget(t *testing.T) {
	t.Parallel()
	requester, origin := compatHTTPFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	source := `try {
  for (let index = 0; index <= ` + strconv.Itoa(maxModuleNetworkCallsPerAction) + `; index++) {
    $httpClient.get({url: "` + origin + `/v1/" + index}, () => {})
  }
  $done({ body: "budget-not-enforced" })
} catch (error) {
  $done({ body: "rejected: " + String(error) })
}`
	result, err := runCompatHTTPScript(t, source, requester)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := stringAnyMap(result.Export())
	body, _ := exported["body"].(string)
	if !strings.Contains(body, "rejected") || !strings.Contains(body, "limit") {
		t.Fatalf("call budget produced %q, want the request limit to be enforced", body)
	}
}
