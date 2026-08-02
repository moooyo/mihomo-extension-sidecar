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

// preparedModuleRequest is what the request phase hands back.
//
// It replaced a four-value return whose middle two booleans read identically at
// every call site. The fourth field is the reason it exists: the response-phase
// candidate set is computed while the outbound headers are built, because that
// is where the post-rewrite URL is known, and the response phase filters it by
// status instead of walking every rule again.
type preparedModuleRequest struct {
	outbound *http.Request
	// handled means the exchange was already answered from a synthetic result
	// and the caller must not dial upstream.
	handled bool
	// bodyBufferRetained means the caller's pre-action body reservation has to
	// stay held past preparation.
	bodyBufferRetained bool
	// responseCandidates is the response-phase match with the status filter not
	// yet applied. Nil when the request was answered or refused.
	responseCandidates []matchedScriptRule
}

func (p *interceptProxy) prepareModuleRequest(w http.ResponseWriter, incoming *http.Request, cfg Config, host string) (*http.Request, bool, error) {
	probe := moduleRequestProbe(incoming, host)
	rules := matchingScriptRules(cfg, "request", probe)
	prepared, err := p.prepareModuleRequestWithRules(w, incoming, cfg, probe, rules)
	return prepared.outbound, prepared.handled, err
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

// requestCanStreamWithoutModuleBuffer reports whether a request nothing will
// read can be forwarded without being read into memory first.
//
// An undeclared length is not a reason to buffer. A chunked HTTP/1.1 upload and
// an HTTP/2 one both arrive with ContentLength -1, and refusing to stream them
// meant a request with zero matched rules -- one this sidecar forwards
// byte-for-byte -- was fully resident and held one of the two body slots for as
// long as the client took to send it.
//
// HTTP/3 is the exception and the guard must stay. roundTripHTTP3 replays the
// request against QUIC version 2 after a version negotiation error, and the
// replay needs GetBody, which only the buffered path supplies.
func requestCanStreamWithoutModuleBuffer(incoming *http.Request, rules []matchedScriptRule) bool {
	if len(rules) > 0 || !requestHasBodySection(incoming) {
		return len(rules) == 0
	}
	return incoming.ProtoMajor != 3 && incoming.ContentLength <= maxModuleHTTPBody
}

func requestCanConditionallyStreamWithModuleActions(incoming *http.Request, rules []matchedScriptRule) bool {
	if len(rules) == 0 || !requestHasPayload(incoming) || incoming.ProtoMajor == 3 ||
		incoming.ContentLength > maxModuleHTTPBody {
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
) (preparedModuleRequest, error) {
	if incoming.ContentLength > maxModuleHTTPBody {
		return preparedModuleRequest{}, fmt.Errorf("request exceeds %d bytes", maxModuleHTTPBody)
	}
	message := probe
	message.Headers = wireHeaders(incoming.Header)
	incomingHadBodySection := requestHasBodySection(incoming)
	if requestCanStreamWithoutModuleBuffer(incoming, requestRules) {
		outbound, responseCandidates, streamErr := streamingModuleRequest(w, incoming, cfg, message)
		return preparedModuleRequest{outbound: outbound, responseCandidates: responseCandidates}, streamErr
	}
	conditionalStream := requestCanConditionallyStreamWithModuleActions(incoming, requestRules)
	bodyBufferRetained := false
	if !conditionalStream {
		body, bodyErr := readDecodedModuleRequestBody(w, incoming, moduleBodyReadLimit(requestRules))
		if bodyErr != nil {
			return preparedModuleRequest{}, bodyErr
		}
		message.Body = body
		bodyBufferRetained = incomingHadBodySection || len(body) > 0 || len(incoming.Trailer) > 0
	}
	message.Headers.Del("Content-Encoding")
	message.Headers.Del("Content-Length")
	urlChanged := false
	bodyChanged := false

	for _, matched := range requestRules {
		// Only once the URL has actually moved.
		//
		// On the probe's own URL this check is provably redundant: the rule only
		// matched because compiledModule.hosts matched the same canonicalised
		// host that moduleCapturesHost looks up, and the URL parsed upstream
		// already, so neither half can fail. It costs three url.Parse calls, a
		// net.ParseIP, a validHostTarget and two canonicalHost passes -- 741ns
		// and 9 allocations measured -- for an answer that cannot be no.
		//
		// After a rewrite it is load-bearing and still runs: that is the case it
		// was written for, and the rewrite itself is separately authorised by
		// authorizeModuleRequestURLRewriteConfig below.
		if urlChanged {
			if err := authorizeModuleRequestActionURL(cfg, matched.Module, message.URL); err != nil {
				return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, fmt.Errorf("extension %s request action: %w", matched.Module.ID, err)
			}
		}
		if matched.Rule.BodyMode != "none" && int64(len(message.Body)) > matched.Rule.MaxBodyBytes {
			return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, fmt.Errorf("extension %s request body exceeds action limit", matched.Module.ID)
		}
		result, err := p.scripts.execute(incoming.Context(), cfg, p.upstreamRoots, matched.Module, matched.Rule, message, nil)
		if err != nil {
			return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, err
		}
		if result.Abort {
			// The server owns an unread request body. Closing it here may
			// synchronously drain it and trigger 100 Continue before aborting.
			panic(http.ErrAbortHandler)
		}
		if err := validateModuleResultBody(matched.Module, matched.Rule, "request", result); err != nil {
			return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, err
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
			return preparedModuleRequest{handled: true}, nil
		}
		if result.ChangedURL {
			parsed, authorizeErr := authorizeModuleRequestURLRewriteConfig(cfg, matched.Module, message.URL, result.URL)
			if authorizeErr != nil {
				return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, fmt.Errorf("extension %s request URL rewrite: %w", matched.Module.ID, authorizeErr)
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
				return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, err
			}
		case urlChanged:
			body, bodyErr := readDecodedModuleRequestBody(w, incoming, moduleBodyReadLimit(requestRules))
			if bodyErr != nil {
				return preparedModuleRequest{}, bodyErr
			}
			message.Body = body
			bodyBufferRetained = true
		default:
			outbound, responseCandidates, streamErr := streamingModuleRequest(w, incoming, cfg, message)
			return preparedModuleRequest{outbound: outbound, responseCandidates: responseCandidates}, streamErr
		}
	}

	outbound, responseCandidates, err := bufferedModuleRequest(incoming, cfg, message, incomingHadBodySection)
	if err != nil {
		return preparedModuleRequest{bodyBufferRetained: bodyBufferRetained}, err
	}
	return preparedModuleRequest{
		outbound: outbound, bodyBufferRetained: bodyBufferRetained, responseCandidates: responseCandidates,
	}, nil
}

// outboundModuleRequest builds the upstream request both module paths send.
//
// WithContext rather than Clone: Clone deep-copies the URL and the Header, and
// both are dead on the next two lines -- the URL is replaced by the parsed
// post-rewrite one and the Header by forwardRequestHeaders, which is itself a
// clone of the projection. Trailer is the one field that must stay deep, because
// streamingModuleRequest hands the outbound map to requestTrailerBody as the
// destination it writes the late trailers into; aliasing it would write them
// back into the inbound request's own map.
func outboundModuleRequest(incoming *http.Request, parsedURL *url.URL, header http.Header) *http.Request {
	outbound := incoming.WithContext(incoming.Context())
	outbound.URL = parsedURL
	outbound.Host = parsedURL.Host
	outbound.RequestURI = ""
	outbound.Header = header
	outbound.Trailer = incoming.Trailer.Clone()
	return outbound
}

func streamingModuleRequest(w http.ResponseWriter, incoming *http.Request, cfg Config, message scriptMessage) (*http.Request, []matchedScriptRule, error) {
	parsedURL, err := url.Parse(message.URL)
	if err != nil {
		return nil, nil, err
	}
	responseCandidates := matchingScriptRulesParsed(cfg, "response", message, false, parsedURL)
	outbound := outboundModuleRequest(incoming, parsedURL, forwardRequestHeaders(message, responseCandidates))
	if requestHasBodySection(incoming) {
		outbound.Body = &requestTrailerBody{
			ReadCloser:  http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody),
			source:      incoming.Trailer,
			destination: outbound.Trailer,
		}
	}
	return outbound, responseCandidates, nil
}

// forwardRequestHeaders builds the headers for the upstream leg of message.
//
// Accept-Encoding is pinned to identity only when a response action could still
// run on this exchange, because transformModuleResponse has to decode the
// upstream body and decodeContentBody understands only gzip, deflate and br.
// When nothing will read that body, the client's own negotiation is forwarded
// untouched so the metered origin leg stays compressed — and so a client that
// explicitly refused identity is not answered with it anyway.
//
// The caller supplies responseCandidates, the status-agnostic response-phase
// match against this same post-rewrite message. It is a superset of the
// response-time match -- the status code is the only thing unknown here -- so
// the response phase filters it rather than walking every rule a second time.
func forwardRequestHeaders(message scriptMessage, responseCandidates []matchedScriptRule) http.Header {
	headers := cloneProxyHeaders(message.Headers)
	sanitizeForwardRequestHeaders(headers)
	if len(responseCandidates) > 0 {
		headers.Set("Accept-Encoding", "identity")
	}
	return headers
}

// responseRulesForStatus applies the one predicate the request-time probe could
// not evaluate. matchingScriptRulesWithStatus differs from its matchStatus=false
// form by exactly this check, so filtering the probe here is identical to
// walking every rule again -- and the walk it replaces also re-parsed the URL.
func responseRulesForStatus(candidates []matchedScriptRule, status int) []matchedScriptRule {
	var filtered []matchedScriptRule
	for index, candidate := range candidates {
		if len(candidate.Rule.Match.StatusCodes) > 0 && !containsInt(candidate.Rule.Match.StatusCodes, status) {
			if filtered == nil {
				filtered = append(make([]matchedScriptRule, 0, len(candidates)), candidates[:index]...)
			}
			continue
		}
		if filtered != nil {
			filtered = append(filtered, candidate)
		}
	}
	if filtered == nil {
		return candidates
	}
	return filtered
}

func bufferedModuleRequest(incoming *http.Request, cfg Config, message scriptMessage, incomingHadBodySection bool) (*http.Request, []matchedScriptRule, error) {
	parsedURL, err := url.Parse(message.URL)
	if err != nil {
		return nil, nil, err
	}
	responseCandidates := matchingScriptRulesParsed(cfg, "response", message, false, parsedURL)
	outbound := outboundModuleRequest(incoming, parsedURL, forwardRequestHeaders(message, responseCandidates))
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
	return outbound, responseCandidates, nil
}

// moduleBodyReadLimit is the largest body any matched action could accept.
//
// An action whose BodyMode is "none" never reads the body, so it does not
// constrain the read. That distinction is the whole design: reading with
// MaxBodyBytes directly was tried and reverted, because it let such an action's
// limit become a ceiling on the whole message and failed the read before the
// per-rule loop could exempt it -- turning an upstream exchange that had already
// succeeded into a 502. Taking the maximum over only the actions that do read a
// body leaves those per-rule checks as the authority for which action refuses,
// and merely stops the process holding bytes no matched action could ever accept.
//
// No interested action means nothing reads the body and the global cap stands:
// the message still has to be forwarded.
//
// This bounds the wire read only. On the RESPONSE path the decode limit
// deliberately stays at the global cap, because transformModuleResponse treats
// any decode failure as "cannot filter this, forward it untouched" -- so a
// tighter decode bound there would convert a fail-closed refusal into a silently
// unfiltered response. The request path is the opposite: a decode failure
// propagates out of prepareModuleRequestWithRules and becomes a 502, exactly
// like the per-rule "request body exceeds action limit" check, so it can and
// does use this limit for the decode too. Without that, an action declaring
// maxBodyBytes 1024 still let a client hold a fully expanded body resident --
// brotli reaches the 64 MiB cap from ~106 bytes on the wire -- while occupying
// one of the two body slots.
func moduleBodyReadLimit(rules []matchedScriptRule) int64 {
	limit := int64(0)
	for _, matched := range rules {
		if matched.Rule.BodyMode == "none" {
			continue
		}
		if matched.Rule.MaxBodyBytes > limit {
			limit = matched.Rule.MaxBodyBytes
		}
	}
	if limit <= 0 || limit > maxModuleHTTPBody {
		return maxModuleHTTPBody
	}
	return limit
}

func readDecodedModuleRequestBody(w http.ResponseWriter, incoming *http.Request, readLimit int64) ([]byte, error) {
	if incoming.Body == nil {
		return nil, nil
	}
	encoding, err := normalizedContentEncoding(incoming.Header)
	if err != nil {
		return nil, err
	}
	incoming.Body = http.MaxBytesReader(w, incoming.Body, maxModuleHTTPBody)
	defer incoming.Body.Close()
	body, err := readBounded(incoming.Body, readLimit)
	if err != nil {
		return nil, err
	}
	return decodeContentBody(body, encoding, readLimit)
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
	limit := rule.MaxBodyBytes
	if rule.Mock != nil {
		// A mock's body is declared in the manifest, not read off the wire, and
		// MockResponse.validate already sizes it against maxMockBodyBytes. Using
		// the action's max_body_bytes here too meant a manifest could describe a
		// mock it is not allowed to serve: `maxBodyBytes: 1024` beside a 2 KiB
		// body -- an ordinary thing to copy from a neighbouring action -- failed
		// every matching request with a 502, and no validator objected. The
		// field bounds the message this action reads, and a mock reads none.
		limit = maxMockBodyBytes
	}
	return validateModuleResultBodySize(module.ID, rule.ID, phase, limit, int64(len(result.Body)))
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
	}
	// MaxBodyBytes bounds what an action is willing to be handed, not what the
	// upstream is allowed to send. Reading with it made the smallest legal value
	// a ceiling on the whole response: readBounded failed before the per-rule
	// check below could exempt a "none" mode action, and the upstream request had
	// already succeeded, so the client got a 502. The request path already reads
	// with the global cap and checks per rule afterwards.
	responseMessage.Headers = wireHeaders(response.Header)
	encoding, err := normalizedContentEncoding(responseMessage.Headers)
	if err != nil {
		p.reportSkippedResponseActions(request, scripts, err)
		return nil, nil
	}
	body, err := readBounded(response.Body, moduleBodyReadLimit(scripts))
	if err != nil {
		return nil, err
	}
	if encoding == "" && isGzip(body) {
		encoding = "gzip"
	}
	decoded, err := decodeContentBody(body, encoding, maxModuleHTTPBody)
	if err != nil {
		// An upstream body this sidecar cannot decode cannot be projected into a
		// script message, and refusing to serve it turns an origin's choice of
		// coding into a 502 for a request that already succeeded. readBounded
		// only returns once the upstream reader reached EOF, so everything the
		// origin sent is in body: hand it back for the caller to stream, keeping
		// the upstream closer so the connection is still released.
		response.Body = struct {
			io.Reader
			io.Closer
		}{bytes.NewReader(body), response.Body}
		p.reportSkippedResponseActions(request, scripts, err)
		return nil, nil
	}
	responseMessage.Body = decoded
	responseTrailers, err := wireTrailers(response.Trailer)
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

// reportSkippedResponseActions records that a response streamed through with its
// matched actions unrun, because the sidecar could not decode the coding the
// origin chose. Reported per action on its own log stream, the way the runtime
// reports an action that timed out or was canceled, so the extension an operator
// is debugging names itself rather than leaving a silent passthrough.
func (p *interceptProxy) reportSkippedResponseActions(request *http.Request, scripts []matchedScriptRule, reason error) {
	if !engineLogPublishingEnabled(p.scripts.logs) {
		return
	}
	for _, matched := range scripts {
		p.scripts.logs.Publish(EngineLog{
			Level: "warn", Source: "engine", Extension: matched.Module.ID, Action: matched.Rule.ID,
			Phase: matched.Rule.Phase, URL: sanitizeEngineLogURL(request.URL.String()),
			ScriptDigest: matched.Rule.ScriptDigest,
			Message:      "action skipped: " + reason.Error(),
		})
	}
}

func writeBufferedModuleResponse(w http.ResponseWriter, method string, status int, headers, trailers http.Header, body []byte) error {
	controller := http.NewResponseController(w)
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
		buffered := &transferDeadlineWriter{Writer: w, controller: controller, timeout: interceptTransferStallTimeout}
		written, err := buffered.Write(body)
		if err != nil {
			return err
		}
		if written != len(body) {
			return io.ErrShortWrite
		}
	}
	if len(declared) > 0 {
		if err := controller.Flush(); err != nil {
			return err
		}
	}
	publishResponseTrailers(w.Header(), trailers, declared)
	return nil
}
