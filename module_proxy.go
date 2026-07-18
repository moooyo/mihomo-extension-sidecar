package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

const maxModuleHTTPBody = int64(64 << 20)

type transformedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (p *interceptProxy) prepareModuleRequest(w http.ResponseWriter, incoming *http.Request, cfg Config, host string) (*http.Request, bool, error) {
	scheme := "http"
	if incoming.TLS != nil || incoming.ProtoMajor == 3 {
		scheme = "https"
	}
	requestURL := scheme + "://" + host + incoming.URL.RequestURI()
	for _, matched := range matchingRewriteRules(cfg, requestURL) {
		switch matched.Rule.Action {
		case "reject", "reject-drop":
			http.Error(w, "request rejected by interception module", http.StatusForbidden)
			return nil, true, nil
		case "reject-200", "reject-dict", "reject-array", "reject-img":
			body := []byte(nil)
			if matched.Rule.Action == "reject-dict" {
				body = []byte("{}")
				w.Header().Set("Content-Type", "application/json")
			} else if matched.Rule.Action == "reject-array" {
				body = []byte("[]")
				w.Header().Set("Content-Type", "application/json")
			} else if matched.Rule.Action == "reject-img" {
				body = []byte{71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 0, 0, 0, 255, 255, 255, 33, 249, 4, 1, 0, 0, 0, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59}
				w.Header().Set("Content-Type", "image/gif")
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return nil, true, nil
		case "redirect-302", "redirect-307":
			status := http.StatusFound
			if matched.Rule.Action == "redirect-307" {
				status = http.StatusTemporaryRedirect
			}
			location := matched.RE.ReplaceAllString(requestURL, matched.Rule.Replacement)
			if _, err := url.ParseRequestURI(location); err != nil {
				return nil, false, fmt.Errorf("module %s produced an invalid redirect: %w", matched.Module.ID, err)
			}
			w.Header().Set("Location", location)
			w.WriteHeader(status)
			return nil, true, nil
		case "rewrite":
			location := matched.RE.ReplaceAllString(requestURL, matched.Rule.Replacement)
			parsed, err := url.Parse(location)
			if err != nil || parsed.User != nil || !activeInterceptHost(cfg, parsed.Hostname()) {
				return nil, false, fmt.Errorf("module %s produced an unsafe URL rewrite", matched.Module.ID)
			}
			requestURL = parsed.String()
		}
	}

	requestBody := []byte(nil)
	if incoming.Body != nil {
		incoming.Body = http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody)
		var err error
		requestBody, err = readBounded(incoming.Body, maxModuleHTTPBody)
		if err != nil {
			return nil, false, err
		}
		requestBody, err = decodeContentBody(requestBody, incoming.Header.Get("Content-Encoding"), maxModuleHTTPBody)
		if err != nil {
			return nil, false, err
		}
	}
	requestHeaders := cloneProxyHeaders(incoming.Header)
	requestHeaders.Del("Content-Encoding")
	requestHeaders.Del("Content-Length")
	for _, matched := range matchingHeaderRules(cfg, requestURL) {
		switch matched.Rule.Operation {
		case "delete":
			requestHeaders.Del(matched.Rule.Header)
		case "add":
			requestHeaders.Add(matched.Rule.Header, matched.Rule.Value)
		case "replace":
			requestHeaders.Set(matched.Rule.Header, matched.Rule.Value)
		}
	}
	message := scriptMessage{
		URL:     requestURL,
		Method:  incoming.Method,
		Headers: requestHeaders,
		Body:    requestBody,
	}
	for _, matched := range matchingScriptRules(cfg, "request", message.URL) {
		if int64(len(message.Body)) > matched.Rule.MaxBodyBytes {
			return nil, false, fmt.Errorf("module %s request body exceeds rule limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(matched.Module, matched.Rule, message, nil)
		if err != nil {
			return nil, false, err
		}
		if result.Abort {
			panic(http.ErrAbortHandler)
		}
		if result.Synthetic {
			status := result.StatusCode
			if status == 0 {
				status = http.StatusOK
			}
			if result.Headers != nil {
				copyResponseHeaders(w.Header(), result.Headers)
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(result.Body)))
			w.WriteHeader(status)
			_, _ = w.Write(result.Body)
			return nil, true, nil
		}
		if result.ChangedURL {
			parsed, err := url.Parse(result.URL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || !activeInterceptHost(cfg, parsed.Hostname()) {
				return nil, false, errors.New("request script attempted to leave the active module allowlist")
			}
			message.URL = parsed.String()
		}
		if result.ChangedHeaders {
			message.Headers = result.Headers
		}
		if result.ChangedBody {
			message.Body = result.Body
		}
	}
	parsedURL, err := url.Parse(message.URL)
	if err != nil {
		return nil, false, err
	}
	outbound := incoming.Clone(incoming.Context())
	outbound.URL = parsedURL
	outbound.Host = parsedURL.Hostname()
	outbound.RequestURI = ""
	outbound.Header = cloneProxyHeaders(message.Headers)
	removeHopByHopHeaders(outbound.Header)
	outbound.Header.Set("Accept-Encoding", "identity")
	outbound.Body = io.NopCloser(bytes.NewReader(message.Body))
	outbound.ContentLength = int64(len(message.Body))
	outbound.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(message.Body)), nil
	}
	if len(message.Body) == 0 && incoming.Body == nil {
		outbound.Body = nil
		outbound.GetBody = nil
		outbound.ContentLength = 0
	}
	return outbound, false, nil
}

func (p *interceptProxy) transformModuleResponse(request *http.Request, response *http.Response, cfg Config) (*transformedResponse, error) {
	requestURL := request.URL.String()
	scripts := matchingScriptRules(cfg, "response", requestURL)
	wloc := cfg.WLOC.Enabled && isBuiltInWLOCHost(request.URL.Hostname()) && request.URL.Path == "/clls/wloc" && response.StatusCode == http.StatusOK
	if len(scripts) == 0 && !wloc {
		return nil, nil
	}
	limit := cfg.WLOC.MaxBodyBytes
	for _, matched := range scripts {
		if matched.Rule.MaxBodyBytes > limit {
			limit = matched.Rule.MaxBodyBytes
		}
	}
	if limit < 1024 || limit > maxModuleHTTPBody {
		limit = maxModuleHTTPBody
	}
	body, err := readBounded(response.Body, limit)
	if err != nil {
		return nil, err
	}
	header := cloneProxyHeaders(response.Header)
	encoding := header.Get("Content-Encoding")
	if encoding == "" && isGzip(body) {
		encoding = "gzip"
	}
	body, err = decodeContentBody(body, encoding, limit)
	if err != nil {
		return nil, err
	}
	header.Del("Content-Encoding")
	if wloc {
		target := wlocTarget{Longitude: *cfg.WLOC.Longitude, Latitude: *cfg.WLOC.Latitude, Accuracy: cfg.WLOC.Accuracy}
		patched, stats, patchErr := patchWLOCBody(body, target, cfg.WLOC.MaxBodyBytes)
		if patchErr != nil {
			if cfg.WLOC.FailClosed {
				return nil, patchErr
			}
			log.Printf("intercept: WLOC patch skipped after error: %v", patchErr)
		} else {
			body = patched
			log.Printf("intercept: patched WLOC response host=%s protocol=%s locations=%d wifi=%d cell=%d", request.URL.Hostname(), request.Proto, stats.Locations, stats.WiFi, stats.Cell)
		}
	}
	requestBody := []byte(nil)
	if len(scripts) > 0 && request.GetBody != nil {
		bodyReader, bodyErr := request.GetBody()
		if bodyErr != nil {
			return nil, bodyErr
		}
		requestBody, bodyErr = readBounded(bodyReader, maxModuleHTTPBody)
		_ = bodyReader.Close()
		if bodyErr != nil {
			return nil, bodyErr
		}
	}
	requestMessage := scriptMessage{
		URL: requestURL, Method: request.Method, Headers: cloneProxyHeaders(request.Header), Body: requestBody,
	}
	responseMessage := scriptMessage{
		URL: requestURL, Headers: header, Body: body, StatusCode: response.StatusCode,
	}
	for _, matched := range scripts {
		if int64(len(responseMessage.Body)) > matched.Rule.MaxBodyBytes {
			return nil, fmt.Errorf("module %s response body exceeds rule limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(matched.Module, matched.Rule, requestMessage, &responseMessage)
		if err != nil {
			return nil, err
		}
		if result.Abort {
			panic(http.ErrAbortHandler)
		}
		if result.ChangedURL {
			return nil, fmt.Errorf("module %s attempted an unsupported response URL mutation", matched.Module.ID)
		}
		if result.ChangedHeaders {
			responseMessage.Headers = result.Headers
		}
		if result.ChangedBody {
			responseMessage.Body = result.Body
		}
		if result.ChangedStatus {
			responseMessage.StatusCode = result.StatusCode
		}
	}
	removeHopByHopHeaders(responseMessage.Headers)
	responseMessage.Headers.Del("Content-Encoding")
	responseMessage.Headers.Del("Content-Length")
	return &transformedResponse{
		StatusCode: responseMessage.StatusCode,
		Header:     responseMessage.Headers,
		Body:       responseMessage.Body,
	}, nil
}

func isBuiltInWLOCHost(host string) bool {
	host = canonicalHost(host)
	for _, candidate := range builtInWLOCHosts {
		if host == candidate {
			return true
		}
	}
	return false
}
