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

func newModuleNetworkAPI(
	vm *goja.Runtime,
	ctx context.Context,
	proxy ProxyConfig,
	roots *x509.CertPool,
	origins []string,
	slots chan struct{},
) *goja.Object {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	calls := 0
	network := vm.NewObject()
	_ = network.Set("request", func(call goja.FunctionCall) goja.Value {
		calls++
		if calls > maxModuleNetworkCallsPerAction {
			panic(vm.NewGoError(errors.New("network.request call limit exceeded")))
		}
		options, ok := stringAnyMap(call.Argument(0).Export())
		if !ok {
			panic(vm.NewTypeError("network.request requires an options object"))
		}
		response, err := performModuleNetworkRequest(ctx, proxy, roots, allowed, slots, options)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("network.request failed: %w", err)))
		}
		body, err := newModuleNetworkByteArray(vm, response.body)
		if err != nil {
			panic(vm.NewGoError(err))
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
		return vm.ToValue(result)
	})
	return network
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
	allowed map[string]struct{},
	slots chan struct{},
	options map[string]any,
) (moduleNetworkResponse, error) {
	for key := range options {
		switch key {
		case "url", "method", "headers", "body":
		default:
			return moduleNetworkResponse{}, fmt.Errorf("unsupported option %q", key)
		}
	}
	rawURL, ok := options["url"].(string)
	if !ok || rawURL == "" || len(rawURL) > 4096 {
		return moduleNetworkResponse{}, errors.New("url must be a non-empty string of at most 4096 bytes")
	}
	parsed, origin, target, err := parseModuleNetworkRequestURL(rawURL)
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	if _, permitted := allowed[origin]; !permitted {
		return moduleNetworkResponse{}, fmt.Errorf("origin %q is not permitted", origin)
	}
	method := http.MethodGet
	if rawMethod, exists := options["method"]; exists {
		method, ok = rawMethod.(string)
		if !ok || !validModuleNetworkMethod(method) {
			return moduleNetworkResponse{}, errors.New("method must be a valid HTTP token")
		}
	}
	headers := make(http.Header)
	if rawHeaders, exists := options["headers"]; exists {
		headers, err = exportedHeaders(rawHeaders)
		if err != nil {
			return moduleNetworkResponse{}, err
		}
	}
	body := []byte(nil)
	if rawBody, exists := options["body"]; exists {
		body, err = exportedBody(rawBody)
		if err != nil {
			return moduleNetworkResponse{}, err
		}
		if int64(len(body)) > maxModuleNetworkRequestBody {
			return moduleNetworkResponse{}, fmt.Errorf("request body exceeds %d bytes", maxModuleNetworkRequestBody)
		}
	}
	if _, exists := headers["User-Agent"]; !exists {
		headers["User-Agent"] = []string{""}
	}
	if _, exists := headers["Accept-Encoding"]; !exists {
		headers.Set("Accept-Encoding", "identity")
	}
	if err := validateModuleNetworkHeaders(headers); err != nil {
		return moduleNetworkResponse{}, err
	}

	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		return moduleNetworkResponse{}, errors.New("network request capacity is busy")
	}
	requestCtx, cancel := context.WithTimeout(ctx, moduleNetworkTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return moduleNetworkResponse{}, err
	}
	request.Header = headers
	request.ContentLength = int64(len(body))
	if _, exists := options["body"]; !exists {
		request.Body = nil
		request.ContentLength = 0
	}

	transport := &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: maxModuleNetworkHeaderBytes,
		ResponseHeaderTimeout:  moduleNetworkTimeout,
		TLSHandshakeTimeout:    moduleNetworkTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil || canonicalHost(host) != target.Host || port != strconv.Itoa(target.Port) {
				return nil, errors.New("transport attempted a target outside the permitted origin")
			}
			return dialSOCKS5TCP(dialCtx, proxy, target)
		},
	}
	defer transport.CloseIdleConnections()
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
	responseHeaders, err := exportedHeaders(response.Header)
	if err != nil {
		return moduleNetworkResponse{}, fmt.Errorf("network response headers: %w", err)
	}
	responseTrailers, err := exportedTrailers(response.Trailer)
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
