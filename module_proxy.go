package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

const maxModuleHTTPBody = int64(64 << 20)

type transformedResponse struct {
	StatusCode int
	Header     http.Header
	Trailer    http.Header
	Body       []byte
}

type requestTrailerBody struct {
	io.ReadCloser
	source      http.Header
	destination http.Header
	once        sync.Once
}

func (b *requestTrailerBody) Read(buffer []byte) (int, error) {
	read, err := b.ReadCloser.Read(buffer)
	if err == io.EOF {
		b.once.Do(func() {
			for name := range b.destination {
				delete(b.destination, name)
			}
			for name, values := range b.source {
				b.destination[name] = append([]string(nil), values...)
			}
		})
	}
	return read, err
}

func (p *interceptProxy) prepareModuleRequest(w http.ResponseWriter, incoming *http.Request, cfg Config, host string) (*http.Request, bool, error) {
	probe := moduleRequestProbe(incoming, host)
	rules := matchingScriptRules(cfg, "request", probe)
	outbound, handled, _, err := p.prepareModuleRequestWithRules(w, incoming, cfg, probe, rules)
	return outbound, handled, err
}

func moduleRequestProbe(incoming *http.Request, host string) scriptMessage {
	scheme := "http"
	if incoming.TLS != nil || incoming.ProtoMajor == 3 {
		scheme = "https"
	}
	return scriptMessage{
		URL: scheme + "://" + host + incoming.URL.RequestURI(), Method: incoming.Method,
	}
}

func requestNeedsModuleBodyReservation(incoming *http.Request, rules []matchedScriptRule) bool {
	if incoming.ContentLength > maxModuleHTTPBody {
		return false
	}
	if len(rules) > 0 {
		return true
	}
	if !requestHasBodySection(incoming) {
		return false
	}
	return !requestCanStreamWithoutModuleBuffer(incoming, rules)
}

func requestCanStreamWithoutModuleBuffer(incoming *http.Request, rules []matchedScriptRule) bool {
	if len(rules) > 0 || !requestHasBodySection(incoming) {
		return len(rules) == 0
	}
	return incoming.ProtoMajor != 3 && incoming.ContentLength >= 0 &&
		incoming.ContentLength <= maxModuleHTTPBody && len(incoming.TransferEncoding) == 0
}

func requestCanConditionallyStreamWithModuleActions(incoming *http.Request, rules []matchedScriptRule) bool {
	if len(rules) == 0 || !requestHasPayload(incoming) || incoming.ProtoMajor == 3 ||
		incoming.ContentLength < 0 || incoming.ContentLength > maxModuleHTTPBody || len(incoming.TransferEncoding) > 0 {
		return false
	}
	encoding, err := normalizedContentEncoding(incoming.Header)
	if err != nil {
		return false
	}
	if encoding != "" && encoding != "identity" {
		return false
	}
	for _, matched := range rules {
		if matched.Rule.BodyMode != "none" {
			return false
		}
	}
	return true
}

// The third result reports whether the caller's pre-action body reservation
// must remain held after request preparation.
func (p *interceptProxy) prepareModuleRequestWithRules(
	w http.ResponseWriter,
	incoming *http.Request,
	cfg Config,
	probe scriptMessage,
	requestRules []matchedScriptRule,
) (*http.Request, bool, bool, error) {
	if incoming.ContentLength > maxModuleHTTPBody {
		return nil, false, false, fmt.Errorf("request exceeds %d bytes", maxModuleHTTPBody)
	}
	requestHeaders, err := exportedHeaders(cloneProxyHeaders(incoming.Header))
	if err != nil {
		return nil, false, false, fmt.Errorf("request headers: %w", err)
	}
	message := probe
	message.Headers = requestHeaders
	incomingHadBodySection := requestHasBodySection(incoming)
	if requestCanStreamWithoutModuleBuffer(incoming, requestRules) {
		outbound, streamErr := streamingModuleRequest(w, incoming, message)
		return outbound, false, false, streamErr
	}
	conditionalStream := requestCanConditionallyStreamWithModuleActions(incoming, requestRules)
	bodyBufferRetained := false
	if !conditionalStream {
		body, bodyErr := readDecodedModuleRequestBody(w, incoming)
		if bodyErr != nil {
			return nil, false, false, bodyErr
		}
		message.Body = body
		bodyBufferRetained = incomingHadBodySection || len(body) > 0 || len(incoming.Trailer) > 0
	}
	message.Headers.Del("Content-Encoding")
	message.Headers.Del("Content-Length")
	urlChanged := false
	bodyChanged := false

	for _, matched := range requestRules {
		if err := authorizeModuleRequestActionURL(cfg, matched.Module, message.URL); err != nil {
			return nil, false, bodyBufferRetained, fmt.Errorf("extension %s request action: %w", matched.Module.ID, err)
		}
		if matched.Rule.BodyMode != "none" && int64(len(message.Body)) > matched.Rule.MaxBodyBytes {
			return nil, false, bodyBufferRetained, fmt.Errorf("extension %s request body exceeds action limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(incoming.Context(), cfg, p.upstreamRoots, matched.Module, matched.Rule, message, nil)
		if err != nil {
			return nil, false, bodyBufferRetained, err
		}
		if result.Abort {
			// The server owns an unread request body. Closing it here may
			// synchronously drain it and trigger 100 Continue before aborting.
			panic(http.ErrAbortHandler)
		}
		if err := validateModuleResultBody(matched.Module, matched.Rule, "request", result); err != nil {
			return nil, false, bodyBufferRetained, err
		}
		if result.Synthetic {
			status := result.StatusCode
			if status == 0 {
				status = http.StatusOK
			}
			if err := writeBufferedModuleResponse(w, incoming.Method, status, result.Headers, result.Trailers, result.Body); err != nil {
				panic(http.ErrAbortHandler)
			}
			// Returning lets net/http close the unread server body after the
			// final response. Direct Close can synchronously drain an upload.
			return nil, true, false, nil
		}
		if result.ChangedURL {
			parsed, authorizeErr := authorizeModuleRequestURLRewriteConfig(cfg, matched.Module, message.URL, result.URL)
			if authorizeErr != nil {
				return nil, false, bodyBufferRetained, fmt.Errorf("extension %s request URL rewrite: %w", matched.Module.ID, authorizeErr)
			}
			message.URL = parsed.String()
			urlChanged = true
		}
		if result.ChangedHeaders {
			message.Headers = result.Headers
		}
		if result.ChangedBody {
			message.Body = result.Body
			bodyChanged = true
			bodyBufferRetained = true
		}
	}
	if conditionalStream {
		switch {
		case bodyChanged:
			if err := drainModuleRequestBody(w, incoming); err != nil {
				return nil, false, bodyBufferRetained, err
			}
		case urlChanged:
			body, bodyErr := readDecodedModuleRequestBody(w, incoming)
			if bodyErr != nil {
				return nil, false, false, bodyErr
			}
			message.Body = body
			bodyBufferRetained = true
		default:
			outbound, streamErr := streamingModuleRequest(w, incoming, message)
			return outbound, false, false, streamErr
		}
	}

	outbound, err := bufferedModuleRequest(incoming, message, incomingHadBodySection)
	if err != nil {
		return nil, false, bodyBufferRetained, err
	}
	return outbound, false, bodyBufferRetained, nil
}

func streamingModuleRequest(w http.ResponseWriter, incoming *http.Request, message scriptMessage) (*http.Request, error) {
	parsedURL, err := url.Parse(message.URL)
	if err != nil {
		return nil, err
	}
	outbound := incoming.Clone(incoming.Context())
	outbound.URL = parsedURL
	outbound.Host = parsedURL.Host
	outbound.RequestURI = ""
	outbound.Header = cloneProxyHeaders(message.Headers)
	if requestHasBodySection(incoming) {
		outbound.Body = &requestTrailerBody{
			ReadCloser:  http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody),
			source:      incoming.Trailer,
			destination: outbound.Trailer,
		}
	}
	sanitizeForwardRequestHeaders(outbound.Header)
	outbound.Header.Set("Accept-Encoding", "identity")
	return outbound, nil
}

func bufferedModuleRequest(incoming *http.Request, message scriptMessage, incomingHadBodySection bool) (*http.Request, error) {
	parsedURL, err := url.Parse(message.URL)
	if err != nil {
		return nil, err
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
	if len(message.Body) == 0 && !incomingHadBodySection && len(outbound.Trailer) == 0 {
		outbound.Body = nil
		outbound.GetBody = nil
		outbound.ContentLength = 0
	}
	return outbound, nil
}

func readDecodedModuleRequestBody(w http.ResponseWriter, incoming *http.Request) ([]byte, error) {
	if incoming.Body == nil {
		return nil, nil
	}
	encoding, err := normalizedContentEncoding(incoming.Header)
	if err != nil {
		return nil, err
	}
	incoming.Body = http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody)
	defer incoming.Body.Close()
	body, err := readBounded(incoming.Body, maxModuleHTTPBody)
	if err != nil {
		return nil, err
	}
	return decodeContentBody(body, encoding, maxModuleHTTPBody)
}

func drainModuleRequestBody(w http.ResponseWriter, incoming *http.Request) error {
	if incoming.Body == nil {
		return nil
	}
	incoming.Body = http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody)
	_, readErr := io.Copy(io.Discard, incoming.Body)
	closeErr := incoming.Body.Close()
	if readErr != nil {
		return readErr
	}
	return closeErr
}

func validateModuleResultBody(module Module, rule ScriptRule, phase string, result scriptResult) error {
	if !result.ChangedBody {
		return nil
	}
	return validateModuleResultBodySize(module.ID, rule.ID, phase, rule.MaxBodyBytes, int64(len(result.Body)))
}

func validateModuleResultBodySize(moduleID, actionID, phase string, actionLimit, size int64) error {
	if size > maxModuleHTTPBody {
		return fmt.Errorf("extension %s %s action %s result body exceeds %d bytes", moduleID, phase, actionID, maxModuleHTTPBody)
	}
	if size > actionLimit {
		return fmt.Errorf("extension %s %s action %s result body exceeds action limit", moduleID, phase, actionID)
	}
	return nil
}

func (p *interceptProxy) transformModuleResponse(
	request *http.Request,
	response *http.Response,
	cfg Config,
	scripts []matchedScriptRule,
) (*transformedResponse, error) {
	if len(scripts) == 0 {
		return nil, nil
	}
	requestMessage := scriptMessage{
		URL: request.URL.String(), Method: request.Method,
		Headers: cloneProxyHeaders(request.Header),
	}
	responseMessage := scriptMessage{
		URL: request.URL.String(), Method: request.Method, StatusCode: response.StatusCode,
		Headers: cloneProxyHeaders(response.Header),
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
	encoding, err := normalizedContentEncoding(responseMessage.Headers)
	if err != nil {
		return nil, err
	}
	body, err := readBounded(response.Body, limit)
	if err != nil {
		return nil, err
	}
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
		if err := validateModuleResultBody(matched.Module, matched.Rule, "response", result); err != nil {
			return nil, err
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
