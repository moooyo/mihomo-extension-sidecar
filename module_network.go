package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const (
	moduleNetworkTimeout            = 5 * time.Second
	maxModuleNetworkRequestBody     = int64(1 << 20)
	maxModuleNetworkResponseBody    = int64(1 << 20)
	maxModuleNetworkHeaderBytes     = int64(64 << 10)
	maxModuleNetworkCallsPerAction  = 4
	maxConcurrentModuleNetworkCalls = 8
)

// moduleNetworkRequester belongs to one action. It never shares transports
// across action or configuration snapshots.
type moduleNetworkRequester struct {
	ctx   context.Context
	proxy ProxyConfig
	roots *x509.CertPool
	// A requester exists only for a module holding the network grant, and that
	// grant no longer carries an origin list. Every other guard still applies:
	// the URL is canonicalized, IP literals and unsafe or private hosts are
	// refused, and the request still leaves through authenticated mihomo SOCKS5.
	slots chan struct{}

	mu         sync.Mutex
	transports map[string]*http.Transport
	closed     bool
}

func newModuleNetworkRequester(
	ctx context.Context,
	proxy ProxyConfig,
	roots *x509.CertPool,
	slots chan struct{},
) *moduleNetworkRequester {
	return &moduleNetworkRequester{
		ctx:        ctx,
		proxy:      proxy,
		roots:      roots,
		slots:      slots,
		transports: make(map[string]*http.Transport),
	}
}

func (r *moduleNetworkRequester) newAPI(vm *goja.Runtime, loop *asyncLoop) *goja.Object {
	calls := 0
	// Both entry points draw on one per-action budget. Counting them separately
	// would let a script double its allowance by mixing the two.
	spend := func() error {
		calls++
		if calls > maxModuleNetworkCallsPerAction {
			return errors.New("network.request call limit exceeded")
		}
		return nil
	}
	network := vm.NewObject()
	_ = network.Set("request", func(call goja.FunctionCall) goja.Value {
		if err := spend(); err != nil {
			panic(vm.NewGoError(err))
		}
		options, ok := stringAnyMap(call.Argument(0).Export())
		if !ok {
			panic(vm.NewTypeError("network.request requires an options object"))
		}
		req, err := newModuleNetworkRequest(options)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("network.request failed: %w", err)))
		}
		response, err := r.request(req)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("network.request failed: %w", err)))
		}
		result, err := moduleNetworkResultObject(vm, response)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return result
	})
	// requestAsync returns a promise so a script can issue several requests at
	// once. The synchronous form holds the VM for the whole round trip, which
	// makes concurrency impossible to express — a port that needs two lookups
	// has to serialize them and pay both latencies.
	//
	// The request runs on a worker goroutine and its completion is posted back
	// to the goroutine that owns the VM, because goja is not goroutine-safe.
	// A failure rejects rather than throws, so `await` inside try/catch reads
	// the same way the synchronous form does.
	if loop != nil {
		_ = network.Set("requestAsync", func(call goja.FunctionCall) goja.Value {
			if err := spend(); err != nil {
				panic(vm.NewGoError(err))
			}
			options, ok := stringAnyMap(call.Argument(0).Export())
			if !ok {
				panic(vm.NewTypeError("network.requestAsync requires an options object"))
			}
			promise, resolve, reject := vm.NewPromise()
			// Built before the worker starts, because the options bag still aliases
			// the script's own maps. A build failure rejects rather than throws:
			// that is the contract this entry point exists to keep, so moving
			// validation onto this goroutine must not change where it surfaces.
			req, buildErr := newModuleNetworkRequest(options)
			if buildErr != nil {
				_ = reject(vm.NewGoError(fmt.Errorf("network.requestAsync failed: %w", buildErr)))
				return vm.ToValue(promise)
			}
			go func() {
				response, err := r.requestWaiting(req)
				loop.post(func() error {
					if err != nil {
						return reject(vm.NewGoError(fmt.Errorf("network.requestAsync failed: %w", err)))
					}
					result, resultErr := moduleNetworkResultObject(vm, response)
					if resultErr != nil {
						return reject(vm.NewGoError(resultErr))
					}
					return resolve(result)
				})
			}()
			return vm.ToValue(promise)
		})
	}
	return network
}

func moduleNetworkResultObject(vm *goja.Runtime, response moduleNetworkResponse) (goja.Value, error) {
	body, err := newModuleNetworkByteArray(vm, response.body)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"url":      response.url,
		"status":   response.status,
		"headers":  response.headers,
		"trailers": response.trailers,
		"body":     body,
	}
	if utf8.Valid(response.body) {
		result["text"] = string(response.body)
	}
	return vm.ToValue(result), nil
}

func (r *moduleNetworkRequester) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	transports := make([]*http.Transport, 0, len(r.transports))
	for _, transport := range r.transports {
		transports = append(transports, transport)
	}
	r.transports = nil
	r.mu.Unlock()

	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

type moduleNetworkResponse struct {
	url      string
	status   int
	headers  map[string][]string
	trailers map[string][]string
	body     []byte
}

func performModuleNetworkRequest(
	ctx context.Context,
	proxy ProxyConfig,
	roots *x509.CertPool,
	slots chan struct{},
	options map[string]any,
) (moduleNetworkResponse, error) {
	requester := newModuleNetworkRequester(ctx, proxy, roots, slots)
	defer requester.Close()
	req, err := newModuleNetworkRequest(options)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	return requester.request(req)
}

// moduleNetworkRequest is a request the requester owns outright.
//
// It exists because the option bag a script hands in is not the requester's to
// read. goja's Export returns the *same* Go map it wrapped, so a bundle writing
// `$httpClient.get({headers: $request.headers}, cb)` and then annotating
// `$request.headers` has the VM goroutine writing the very map a worker
// goroutine would be reading -- `fatal error: concurrent map read and map
// write`, which no recover() can catch and which takes the whole sidecar down
// with every in-flight connection, the SOCKS listeners, the control API, and
// the engine-log socket.
//
// Building this value is therefore part of the call, not part of the round
// trip: newModuleNetworkRequest runs on the goroutine that owns the VM and
// copies everything it needs. That also puts every validation error back on the
// goroutine that can turn it into a real JS exception.
type moduleNetworkRequest struct {
	url     *url.URL
	origin  string
	target  socksTarget
	method  string
	headers http.Header
	body    []byte
	hasBody bool
}

// newModuleNetworkRequest must be called on the goroutine that owns the VM.
//
// exportedHeaders and exportedBody both allocate fresh storage for every field
// they accept, so the returned value shares nothing with the script's map.
func newModuleNetworkRequest(options map[string]any) (moduleNetworkRequest, error) {
	for key := range options {
		switch key {
		case "url", "method", "headers", "body":
		default:
			return moduleNetworkRequest{}, fmt.Errorf("unsupported option %q", key)
		}
	}
	rawURL, ok := options["url"].(string)
	if !ok || rawURL == "" || len(rawURL) > 4096 {
		return moduleNetworkRequest{}, errors.New("url must be a non-empty string of at most 4096 bytes")
	}
	parsed, origin, target, err := parseModuleNetworkRequestURL(rawURL)
	if err != nil {
		return moduleNetworkRequest{}, err
	}
	method := http.MethodGet
	if rawMethod, exists := options["method"]; exists {
		method, ok = rawMethod.(string)
		if !ok || !validModuleNetworkMethod(method) {
			return moduleNetworkRequest{}, errors.New("method must be a valid HTTP token")
		}
	}
	headers := make(http.Header)
	if rawHeaders, exists := options["headers"]; exists {
		headers, err = exportedHeaders(rawHeaders)
		if err != nil {
			return moduleNetworkRequest{}, err
		}
	}
	body := []byte(nil)
	_, hasBody := options["body"]
	if hasBody {
		body, err = exportedBody(options["body"])
		if err != nil {
			return moduleNetworkRequest{}, err
		}
		if int64(len(body)) > maxModuleNetworkRequestBody {
			return moduleNetworkRequest{}, fmt.Errorf("request body exceeds %d bytes", maxModuleNetworkRequestBody)
		}
	}
	if _, exists := headers["User-Agent"]; !exists {
		headers["User-Agent"] = []string{""}
	}
	if _, exists := headers["Accept-Encoding"]; !exists {
		headers.Set("Accept-Encoding", "identity")
	}
	if err := validateModuleNetworkHeaders(headers); err != nil {
		return moduleNetworkRequest{}, err
	}
	return moduleNetworkRequest{
		url:     parsed,
		origin:  origin,
		target:  target,
		method:  method,
		headers: headers,
		body:    body,
		hasBody: hasBody,
	}, nil
}

func (r *moduleNetworkRequester) request(req moduleNetworkRequest) (moduleNetworkResponse, error) {
	return r.performRequest(req, false)
}

// requestWaiting blocks for a concurrency slot instead of failing fast.
//
// Only a caller that has released the VM uses it. A synchronous caller holds
// the VM for the whole request, so waiting there would freeze the script and
// failing immediately is the only safe answer; a caller that has already
// returned to the script -- an awaited request, or a $httpClient call whose
// work runs on a worker goroutine -- can simply settle later. Both are bounded
// by the action deadline, which is what actually stops a script from waiting
// forever.
func (r *moduleNetworkRequester) requestWaiting(req moduleNetworkRequest) (moduleNetworkResponse, error) {
	return r.performRequest(req, true)
}

func (r *moduleNetworkRequester) performRequest(req moduleNetworkRequest, waitForSlot bool) (moduleNetworkResponse, error) {
	parsed, origin, target := req.url, req.origin, req.target
	method, headers, body := req.method, req.headers, req.body

	if waitForSlot {
		select {
		case r.slots <- struct{}{}:
			defer func() { <-r.slots }()
		case <-r.ctx.Done():
			return moduleNetworkResponse{}, r.ctx.Err()
		}
	} else {
		select {
		case r.slots <- struct{}{}:
			defer func() { <-r.slots }()
		default:
			return moduleNetworkResponse{}, errors.New("network request capacity is busy")
		}
	}
	requestCtx, cancel := context.WithTimeout(r.ctx, moduleNetworkTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	request.Header = headers
	request.ContentLength = int64(len(body))
	if !req.hasBody {
		request.Body = nil
		request.ContentLength = 0
	}

	transport, err := r.transport(origin, target)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	defer r.closeTransportIfRequesterClosed(transport)
	client := &http.Client{
		Transport: transport,
		Timeout:   moduleNetworkTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body, maxModuleNetworkResponseBody)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	// wireHeaders, not exportedHeaders: this block came off the wire from the
	// origin the script named, so net/http already parsed and bounded it, and the
	// script budget exportedHeaders enforces is calibrated for what a script
	// invents. Running it here failed the script's own request whenever an origin
	// answered with more fields than that budget allows -- the same conflation
	// wireHeaders was written to end on the proxy path.
	responseHeaders := wireHeaders(response.Header)
	responseTrailers, err := wireTrailers(response.Trailer)
	if err != nil {
		return moduleNetworkResponse{}, fmt.Errorf("network response trailers: %w", err)
	}
	return moduleNetworkResponse{
		url:      response.Request.URL.String(),
		status:   response.StatusCode,
		headers:  map[string][]string(responseHeaders),
		trailers: map[string][]string(responseTrailers),
		body:     responseBody,
	}, nil
}

func (r *moduleNetworkRequester) transport(origin string, target socksTarget) (*http.Transport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("network requester is closed")
	}
	if transport := r.transports[origin]; transport != nil {
		return transport, nil
	}

	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		// One connection per host was all a synchronous caller could ever use.
		// With requestAsync it becomes an artificial serializer: two awaited
		// requests to the same host would queue on the connection and cost both
		// latencies, which is the divergence the async form exists to close.
		// Bounded by the per-action call budget, so an action can never open
		// more connections to a host than it is allowed requests, and the
		// process-wide slot cap still bounds everything in flight.
		MaxConnsPerHost:        maxModuleNetworkCallsPerAction,
		MaxResponseHeaderBytes: maxModuleNetworkHeaderBytes,
		ResponseHeaderTimeout:  moduleNetworkTimeout,
		TLSHandshakeTimeout:    moduleNetworkTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    r.roots,
			// Per-origin transport, so the cache is per origin too. A script that
			// makes several calls to the same host pays one handshake.
			ClientSessionCache: tls.NewLRUClientSessionCache(upstreamSessionCacheEntries),
		},
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil || canonicalHost(host) != target.Host || port != strconv.Itoa(target.Port) {
				return nil, errors.New("transport attempted a target outside the permitted origin")
			}
			return dialSOCKS5TCP(dialCtx, r.proxy, target)
		},
	}
	r.transports[origin] = transport
	return transport, nil
}

func (r *moduleNetworkRequester) closeTransportIfRequesterClosed(transport *http.Transport) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		transport.CloseIdleConnections()
	}
}

func parseModuleNetworkRequestURL(raw string) (*url.URL, string, socksTarget, error) {
	if strings.Contains(raw, "#") {
		return nil, "", socksTarget{}, errors.New("url must be an absolute HTTP URL without credentials or a fragment")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return nil, "", socksTarget{}, errors.New("url must be an absolute HTTP URL without credentials or a fragment")
	}
	originInput := strings.ToLower(parsed.Scheme) + "://" + parsed.Host
	origin, err := canonicalModuleNetworkOrigin(originInput)
	if err != nil {
		return nil, "", socksTarget{}, err
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, "", socksTarget{}, err
	}
	portText := originURL.Port()
	if portText == "" {
		if originURL.Scheme == "https" {
			portText = "443"
		} else {
			portText = "80"
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, "", socksTarget{}, err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = canonicalHost(parsed.Hostname())
	if originURL.Port() != "" {
		parsed.Host = net.JoinHostPort(parsed.Host, originURL.Port())
	}
	return parsed, origin, socksTarget{Host: canonicalHost(originURL.Hostname()), Port: port}, nil
}

func validateModuleNetworkHeaders(headers http.Header) error {
	if err := normalizeRequestTEHeader(headers); err != nil {
		return err
	}
	var size int64
	for name, values := range headers {
		if !validModuleNetworkHeaderName(name) || (isHopByHopHeader(name) && !strings.EqualFold(name, "Te")) {
			return fmt.Errorf("header %q is not permitted", name)
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "proxy-authorization":
			return fmt.Errorf("header %q is managed by the runtime", name)
		}
		size += int64(len(name))
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("header %q contains a line break", name)
			}
			size += int64(len(value))
		}
	}
	if size > maxModuleNetworkHeaderBytes {
		return fmt.Errorf("request headers exceed %d bytes", maxModuleNetworkHeaderBytes)
	}
	return nil
}

func validModuleNetworkMethod(method string) bool {
	if method == "" {
		return false
	}
	for index := 0; index < len(method); index++ {
		if !isModuleNetworkTokenByte(method[index]) {
			return false
		}
	}
	return true
}

func validModuleNetworkHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		if !isModuleNetworkTokenByte(name[index]) {
			return false
		}
	}
	return true
}

func isModuleNetworkTokenByte(value byte) bool {
	if value >= '0' && value <= '9' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func newModuleNetworkByteArray(vm *goja.Runtime, body []byte) (goja.Value, error) {
	constructor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
	if !ok {
		return nil, errors.New("Uint8Array constructor is unavailable")
	}
	return constructor(nil, vm.ToValue(vm.NewArrayBuffer(append([]byte(nil), body...))))
}
