package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const maxModuleHTTPBody = int64(64 << 20)

type transformedResponse struct {
	StatusCode int
	Header     http.Header
	Trailer    http.Header
	Body       []byte
}

func (p *interceptProxy) prepareModuleRequest(w http.ResponseWriter, incoming *http.Request, cfg Config, host string) (*http.Request, bool, error) {
	scheme := "http"
	if incoming.TLS != nil || incoming.ProtoMajor == 3 {
		scheme = "https"
	}
	requestHeaders, err := exportedHeaders(cloneProxyHeaders(incoming.Header))
	if err != nil {
		return nil, false, fmt.Errorf("request headers: %w", err)
	}
	message := scriptMessage{
		URL: scheme + "://" + host + incoming.URL.RequestURI(), Method: incoming.Method,
		Headers: requestHeaders,
	}
	requestRules := matchingScriptRules(cfg, "request", message)
	if incoming.Body != nil {
		incoming.Body = http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody)
		body, err := readBounded(incoming.Body, maxModuleHTTPBody)
		if err != nil {
			return nil, false, err
		}
		body, err = decodeContentBody(body, incoming.Header.Get("Content-Encoding"), maxModuleHTTPBody)
		if err != nil {
			return nil, false, err
		}
		message.Body = body
	}
	message.Headers.Del("Content-Encoding")
	message.Headers.Del("Content-Length")

	for _, matched := range requestRules {
		if err := authorizeModuleRequestActionURL(cfg, matched.Module, message.URL); err != nil {
			return nil, false, fmt.Errorf("extension %s request action: %w", matched.Module.ID, err)
		}
		if matched.Rule.BodyMode != "none" && int64(len(message.Body)) > matched.Rule.MaxBodyBytes {
			return nil, false, fmt.Errorf("extension %s request body exceeds action limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(incoming.Context(), cfg, p.upstreamRoots, matched.Module, matched.Rule, message, nil)
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
			if err := writeBufferedModuleResponse(w, incoming.Method, status, result.Headers, result.Trailers, result.Body); err != nil {
				panic(http.ErrAbortHandler)
			}
			return nil, true, nil
		}
		if result.ChangedURL {
			parsed, authorizeErr := authorizeModuleRequestURLRewriteConfig(cfg, matched.Module, message.URL, result.URL)
			if authorizeErr != nil {
				return nil, false, fmt.Errorf("extension %s request URL rewrite: %w", matched.Module.ID, authorizeErr)
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
	outbound.Host = parsedURL.Host
	outbound.RequestURI = ""
	outbound.Header = cloneProxyHeaders(message.Headers)
	sanitizeForwardRequestHeaders(outbound.Header)
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
	requestMessage := scriptMessage{
		URL: request.URL.String(), Method: request.Method,
		Headers: cloneProxyHeaders(request.Header),
	}
	responseMessage := scriptMessage{
		URL: request.URL.String(), Method: request.Method, StatusCode: response.StatusCode,
		Headers: cloneProxyHeaders(response.Header),
	}
	scripts := matchingScriptRules(cfg, "response", responseMessage)
	if len(scripts) == 0 {
		return nil, nil
	}
	limit := int64(1024)
	for _, matched := range scripts {
		if matched.Rule.MaxBodyBytes > limit {
			limit = matched.Rule.MaxBodyBytes
		}
	}
	if limit > maxModuleHTTPBody {
		limit = maxModuleHTTPBody
	}
	responseHeaders, err := exportedHeaders(response.Header)
	if err != nil {
		return nil, fmt.Errorf("upstream response headers: %w", err)
	}
	responseMessage.Headers = responseHeaders
	body, err := readBounded(response.Body, limit)
	if err != nil {
		return nil, err
	}
	encoding := responseMessage.Headers.Get("Content-Encoding")
	if encoding == "" && isGzip(body) {
		encoding = "gzip"
	}
	body, err = decodeContentBody(body, encoding, limit)
	if err != nil {
		return nil, err
	}
	responseMessage.Body = body
	responseTrailers, err := exportedTrailers(response.Trailer)
	if err != nil {
		return nil, fmt.Errorf("upstream response trailers: %w", err)
	}
	responseMessage.Trailers = responseTrailers
	responseMessage.Headers.Del("Content-Encoding")
	responseMessage.Headers.Del("Content-Length")

	for _, matched := range scripts {
		if matched.Rule.BodyMode != "none" && int64(len(responseMessage.Body)) > matched.Rule.MaxBodyBytes {
			return nil, fmt.Errorf("extension %s response body exceeds action limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(request.Context(), cfg, p.upstreamRoots, matched.Module, matched.Rule, requestMessage, &responseMessage)
		if err != nil {
			return nil, err
		}
		if result.Abort {
			panic(http.ErrAbortHandler)
		}
		if result.ChangedURL {
			return nil, errors.New("response action attempted an unsupported URL mutation")
		}
		if result.ChangedHeaders {
			responseMessage.Headers = result.Headers
		}
		if result.ChangedTrailers {
			responseMessage.Trailers = result.Trailers
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
		Trailer:    responseMessage.Trailers,
		Body:       responseMessage.Body,
	}, nil
}

func writeBufferedModuleResponse(w http.ResponseWriter, method string, status int, headers, trailers http.Header, body []byte) error {
	canHaveBody := responseCanHaveBody(method, status)
	if len(body) > 0 && !canHaveBody {
		return http.ErrBodyNotAllowed
	}
	if len(responseTrailerNames(trailers)) > 0 && !canHaveBody {
		return errors.New("response trailers require a response body section")
	}
	copyResponseHeaders(w.Header(), headers)
	removeHopByHopHeaders(w.Header())
	w.Header().Del("Content-Encoding")
	declared := declareResponseTrailers(w.Header(), trailers)
	if len(declared) == 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		written, err := w.Write(body)
		if err != nil {
			return err
		}
		if written != len(body) {
			return io.ErrShortWrite
		}
	}
	if len(declared) > 0 {
		if err := http.NewResponseController(w).Flush(); err != nil {
			return err
		}
	}
	publishResponseTrailers(w.Header(), trailers, declared)
	return nil
}
