package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type interceptProxy struct {
	config        *configStore
	certificates  *certificateStore
	upstreamRoots *x509.CertPool
	scripts       *scriptRuntime
	bodySlots     chan struct{}
}

func newInterceptProxy(config *configStore, certificates *certificateStore) *interceptProxy {
	scripts := newScriptRuntime("/var/lib/5gpn-intercept/store.json")
	if cfg, err := config.Current(); err == nil {
		scripts.prune(cfg.Modules)
	}
	return &interceptProxy{config: config, certificates: certificates, scripts: scripts, bodySlots: make(chan struct{}, 2)}
}

func (p *interceptProxy) Serve(ctx context.Context, listener net.Listener) error {
	var connections sync.WaitGroup
	defer connections.Wait()
	go p.pruneExtensionState(ctx)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		connections.Add(1)
		go func(conn net.Conn) {
			defer connections.Done()
			sessionDone := make(chan struct{})
			defer close(sessionDone)
			go func() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
				case <-sessionDone:
				}
			}()
			if err := p.handleSOCKSConnection(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("intercept: SOCKS session failed: %v", err)
			}
		}(conn)
	}
}

func (p *interceptProxy) pruneExtensionState(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cfg, err := p.config.Current(); err == nil {
				p.scripts.prune(cfg.Modules)
			}
		}
	}
}

func (p *interceptProxy) handleSOCKSConnection(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	cfg, err := p.config.Current()
	if err != nil {
		return err
	}
	p.scripts.prune(cfg.Modules)
	command, target, err := readSOCKSRequest(conn, cfg.Username, cfg.Password)
	if err != nil {
		return err
	}
	switch command {
	case socksCommandConnect:
		if !allowedInboundSOCKSTarget(cfg, target) {
			_ = writeSOCKSReply(conn, 2, nil)
			return errors.New("SOCKS CONNECT target is outside the active extension allowlist")
		}
		if err := writeSOCKSReply(conn, 0, conn.LocalAddr()); err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Time{})
		if target.Port == 80 {
			return p.servePlainHTTPConnection(conn)
		}
		return p.serveTLSConnection(conn)
	case socksCommandUDP:
		return p.serveUDPAssociation(ctx, conn)
	default:
		_ = writeSOCKSReply(conn, 7, nil)
		return fmt.Errorf("unsupported SOCKS command %d", command)
	}
}

func (p *interceptProxy) servePlainHTTPConnection(conn net.Conn) error {
	listener := newSingleConnListener(conn)
	server := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (p *interceptProxy) serveTLSConnection(conn net.Conn) error {
	cfg, err := p.config.Current()
	if err != nil {
		return err
	}
	listener := newSingleConnListener(conn)
	server := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: p.certificates.GetCertificate,
			NextProtos:     mitmTLSNextProtos(cfg.MITM.HTTP2),
		},
	}
	err = server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func mitmTLSNextProtos(http2 bool) []string {
	if http2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (p *interceptProxy) serveUDPAssociation(ctx context.Context, control net.Conn) error {
	localHost, _, err := net.SplitHostPort(control.LocalAddr().String())
	if err != nil {
		return err
	}
	udpAddress := &net.UDPAddr{IP: net.ParseIP(localHost).To4(), Port: 0}
	udpConn, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		_ = writeSOCKSReply(control, 1, nil)
		return err
	}
	remoteHost, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err != nil {
		udpConn.Close()
		return err
	}
	packetConn := &socksServerPacketConn{conn: udpConn, allowedIP: net.ParseIP(remoteHost), config: p.config}
	defer packetConn.Close()
	if err := writeSOCKSReply(control, 0, udpConn.LocalAddr()); err != nil {
		packetConn.Close()
		return err
	}
	_ = control.SetDeadline(time.Time{})
	cfg, err := p.config.Current()
	if err != nil {
		return err
	}
	if cfg.MITM.QUICFallbackProtection {
		return discardQUICAssociation(ctx, control, packetConn)
	}
	server := &http3.Server{
		Handler:        p,
		MaxHeaderBytes: 64 << 10,
		IdleTimeout:    90 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: p.certificates.GetCertificate,
		},
		QUICConfig: &quic.Config{
			Versions:        []quic.Version{quic.Version1, quic.Version2},
			MaxIdleTimeout:  90 * time.Second,
			KeepAlivePeriod: 20 * time.Second,
			Allow0RTT:       false,
		},
	}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(packetConn) }()
	controlClosed := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = control.Read(one[:])
		close(controlClosed)
	}()
	select {
	case <-ctx.Done():
	case <-controlClosed:
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	_ = server.Close()
	_ = packetConn.Close()
	return nil
}

func discardQUICAssociation(ctx context.Context, control net.Conn, packetConn net.PacketConn) error {
	controlClosed := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = control.Read(one[:])
		close(controlClosed)
	}()
	discardErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			if _, _, err := packetConn.ReadFrom(buffer); err != nil {
				discardErr <- err
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-controlClosed:
		return nil
	case err := <-discardErr:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (p *interceptProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := canonicalHost(r.Host)
	cfg, err := p.config.Current()
	if err != nil {
		http.Error(w, "interception configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	if !activeInterceptHost(cfg, host) {
		http.Error(w, "unrecognized interception host", http.StatusMisdirectedRequest)
		return
	}
	bufferSlot := requestHasPayload(r)
	if bufferSlot && !p.acquireBodySlot() {
		http.Error(w, "interception body capacity is busy", http.StatusServiceUnavailable)
		return
	}
	if bufferSlot {
		defer p.releaseBodySlot()
	}
	outbound, handled, prepareErr := p.prepareModuleRequest(w, r, cfg, host)
	if handled {
		return
	}
	if prepareErr != nil {
		log.Printf("intercept: request transformation failed host=%s: %v", host, prepareErr)
		http.Error(w, "interception request transformation failed", http.StatusBadGateway)
		return
	}

	response, cleanup, err := p.roundTrip(outbound, cfg)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		log.Printf("intercept: upstream request failed host=%s protocol=%s: %v", host, r.Proto, err)
		http.Error(w, "interception upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseProbe := scriptMessage{
		URL: outbound.URL.String(), Method: outbound.Method, StatusCode: response.StatusCode,
		Headers: response.Header,
	}
	if !bufferSlot && len(matchingScriptRules(cfg, "response", responseProbe)) > 0 {
		if !p.acquireBodySlot() {
			http.Error(w, "interception body capacity is busy", http.StatusServiceUnavailable)
			return
		}
		defer p.releaseBodySlot()
	}

	transformed, transformErr := p.transformModuleResponse(outbound, response, cfg)
	if transformErr != nil {
		log.Printf("intercept: response transformation failed host=%s protocol=%s: %v", host, r.Proto, transformErr)
		http.Error(w, "interception response transformation failed", http.StatusBadGateway)
		return
	}
	if transformed != nil {
		if writeErr := writeBufferedModuleResponse(w, r.Method, transformed.StatusCode, transformed.Header, transformed.Trailer, transformed.Body); writeErr != nil {
			log.Printf("intercept: transformed response write failed host=%s protocol=%s: %v", host, r.Proto, writeErr)
			panic(http.ErrAbortHandler)
		}
		return
	}

	if copyErr := writeStreamingProxyResponse(w, r.ProtoMajor, r.Method, response); copyErr != nil {
		log.Printf("intercept: upstream response copy failed host=%s protocol=%s: %v", host, r.Proto, copyErr)
		panic(http.ErrAbortHandler)
	}
}

func (p *interceptProxy) acquireBodySlot() bool {
	if p.bodySlots == nil {
		return true
	}
	select {
	case p.bodySlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *interceptProxy) releaseBodySlot() {
	if p.bodySlots != nil {
		<-p.bodySlots
	}
}

func requestHasPayload(request *http.Request) bool {
	return request != nil && request.Body != nil && (request.ContentLength != 0 || len(request.TransferEncoding) > 0)
}

func (p *interceptProxy) roundTrip(request *http.Request, cfg Config) (*http.Response, func(), error) {
	if request.ProtoMajor == 3 {
		return roundTripHTTP3(request, cfg, p.upstreamRoots)
	}
	transport := p.newHTTPTransport(cfg)
	response, err := transport.RoundTrip(request)
	cleanup := func() { transport.CloseIdleConnections() }
	return response, cleanup, err
}

func (p *interceptProxy) newHTTPTransport(cfg Config) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      cfg.MITM.HTTP2,
		MaxResponseHeaderBytes: maxModuleNetworkHeaderBytes,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.upstreamRoots,
		},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("upstream TCP target is outside the active extension allowlist")
			}
			target, permitted := activeModuleUpstreamTarget(cfg, host, portText)
			if !permitted {
				return nil, errors.New("upstream TCP target is outside the active extension allowlist")
			}
			return dialSOCKS5TCP(ctx, cfg.UpstreamProxy, target)
		},
	}
}

func roundTripHTTP3(request *http.Request, cfg Config, roots *x509.CertPool) (*http.Response, func(), error) {
	response, cleanup, err := roundTripHTTP3Version(request, cfg, roots, quic.Version1)
	if err == nil {
		return response, cleanup, nil
	}
	var versionError *quic.VersionNegotiationError
	if !errors.As(err, &versionError) || !containsQUICVersion(versionError.Theirs, quic.Version2) {
		return nil, nil, err
	}
	if request.GetBody != nil {
		body, bodyErr := request.GetBody()
		if bodyErr != nil {
			return nil, nil, bodyErr
		}
		request.Body = body
	}
	return roundTripHTTP3Version(request, cfg, roots, quic.Version2)
}

func roundTripHTTP3Version(request *http.Request, cfg Config, roots *x509.CertPool, version quic.Version) (*http.Response, func(), error) {
	host := canonicalHost(request.URL.Host)
	portText := request.URL.Port()
	if portText == "" {
		portText = "443"
	}
	target, permitted := activeModuleUpstreamTarget(cfg, host, portText)
	if !permitted {
		return nil, nil, errors.New("upstream QUIC target is outside the active extension allowlist")
	}
	packetConn, err := dialSOCKS5UDP(request.Context(), cfg.UpstreamProxy, target)
	if err != nil {
		return nil, nil, err
	}
	quicTransport := &quic.Transport{Conn: packetConn}
	h3Transport := &http3.Transport{
		MaxResponseHeaderBytes: int(maxModuleNetworkHeaderBytes),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
			RootCAs:    roots,
		},
		QUICConfig: &quic.Config{
			Versions:        []quic.Version{version},
			MaxIdleTimeout:  90 * time.Second,
			KeepAlivePeriod: 20 * time.Second,
		},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quicTransport.Dial(ctx, target, tlsConfig, quicConfig)
		},
	}
	cleanup := func() {
		_ = h3Transport.Close()
		_ = quicTransport.Close()
		_ = packetConn.Close()
	}
	response, err := h3Transport.RoundTrip(request)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return response, cleanup, nil
}

func containsQUICVersion(versions []quic.Version, want quic.Version) bool {
	for _, version := range versions {
		if version == want {
			return true
		}
	}
	return false
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}

func cloneProxyHeaders(source http.Header) http.Header {
	clone := make(http.Header, len(source))
	for name, values := range source {
		clone[name] = append([]string(nil), values...)
	}
	return clone
}

func copyResponseHeaders(destination, source http.Header) {
	for name, values := range source {
		if isHopByHopHeader(name) || connectionListsHeader(source, name) {
			continue
		}
		destination[name] = append([]string(nil), values...)
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if validModuleNetworkHeaderName(name) {
				header.Del(name)
			}
		}
	}
	for name := range header {
		if isHopByHopHeader(name) {
			header.Del(name)
		}
	}
}

func validateNativePatchHeaders(headers http.Header, response bool) error {
	if !response {
		if err := normalizeRequestTEHeader(headers); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !isHopByHopHeader(name) || (!response && strings.EqualFold(name, "Te")) {
			continue
		}
		phase := "request"
		if response {
			phase = "response"
		}
		return fmt.Errorf("header %q is not permitted in a native %s patch", name, phase)
	}
	return nil
}

func sanitizeForwardRequestHeaders(headers http.Header) {
	preserveTrailers := requestTEIsTrailers(headers)
	removeHopByHopHeaders(headers)
	if preserveTrailers {
		headers.Set("Te", "trailers")
	}
}

func requestTEIsTrailers(headers http.Header) bool {
	var values []string
	fields := 0
	for name, fieldValues := range headers {
		if strings.EqualFold(name, "Te") {
			fields++
			values = append(values, fieldValues...)
		}
	}
	return fields == 1 && len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "trailers")
}

func connectionListsHeader(headers http.Header, want string) bool {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(name), want) {
				return true
			}
		}
	}
	return false
}

func normalizeRequestTEHeader(headers http.Header) error {
	var names []string
	for name := range headers {
		if strings.EqualFold(name, "Te") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	if len(names) != 1 {
		return fmt.Errorf("duplicate TE header names %q", names)
	}
	values := headers[names[0]]
	if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "trailers") {
		return errors.New("TE header must contain exactly trailers")
	}
	delete(headers, names[0])
	headers.Set("Te", "trailers")
	return nil
}

func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func validResponseTrailerName(name string) bool {
	if !validModuleNetworkHeaderName(name) {
		return false
	}
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(canonical, "If-") {
		return false
	}
	switch canonical {
	case "Authorization", "Cache-Control", "Connection", "Content-Encoding", "Content-Length", "Content-Range", "Content-Type",
		"Expect", "Host", "Keep-Alive", "Max-Forwards", "Pragma", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Range", "Realm", "Te", "Trailer", "Transfer-Encoding", "Www-Authenticate":
		return false
	default:
		return true
	}
}

func responseTrailerNames(trailers http.Header) []string {
	seen := make(map[string]struct{}, len(trailers))
	for name := range trailers {
		canonical := http.CanonicalHeaderKey(name)
		if !validResponseTrailerName(canonical) {
			continue
		}
		seen[canonical] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func declareResponseTrailers(header, trailers http.Header) []string {
	header.Del("Trailer")
	names := responseTrailerNames(trailers)
	if len(names) == 0 {
		return nil
	}
	header.Del("Content-Length")
	header.Set("Trailer", strings.Join(names, ", "))
	return names
}

func publishResponseTrailers(header, trailers http.Header, declared []string) {
	declaredSet := make(map[string]struct{}, len(declared))
	for _, name := range declared {
		declaredSet[name] = struct{}{}
	}
	for _, name := range responseTrailerNames(trailers) {
		values := responseTrailerValues(trailers, name)
		if _, exists := declaredSet[name]; exists {
			header[name] = values
			continue
		}
		header[http.TrailerPrefix+name] = values
	}
}

func responseTrailerValues(trailers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range trailers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func writeStreamingProxyResponse(w http.ResponseWriter, downstreamProtoMajor int, method string, response *http.Response) error {
	responseHeaders, err := exportedHeaders(response.Header)
	if err != nil {
		return fmt.Errorf("upstream response headers: %w", err)
	}
	announcedTrailers, err := exportedTrailers(response.Trailer)
	if err != nil {
		return fmt.Errorf("upstream response trailers: %w", err)
	}
	canHaveBody := responseCanHaveBody(method, response.StatusCode)
	if len(responseTrailerNames(announcedTrailers)) > 0 && !canHaveBody {
		return errors.New("response trailers require a response body section")
	}
	copyResponseHeaders(w.Header(), responseHeaders)
	declaredTrailers := declareResponseTrailers(w.Header(), announcedTrailers)
	forceChunked := downstreamProtoMajor == 1 && response.ProtoMajor >= 2 && canHaveBody
	if forceChunked {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(response.StatusCode)
	if forceChunked {
		if err := http.NewResponseController(w).Flush(); err != nil {
			return err
		}
	}
	if _, err := io.Copy(w, response.Body); err != nil {
		return err
	}
	responseTrailers, err := exportedTrailers(response.Trailer)
	if err != nil {
		return fmt.Errorf("upstream response trailers: %w", err)
	}
	if len(responseTrailerNames(responseTrailers)) > 0 && !canHaveBody {
		return errors.New("response trailers require a response body section")
	}
	if len(responseTrailerNames(responseTrailers)) > 0 {
		if err := http.NewResponseController(w).Flush(); err != nil {
			return err
		}
	}
	publishResponseTrailers(w.Header(), responseTrailers, declaredTrailers)
	return nil
}

func responseCanHaveBody(method string, status int) bool {
	if method == http.MethodHead || status >= 100 && status <= 199 {
		return false
	}
	return status != http.StatusNoContent && status != http.StatusNotModified
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	done := make(chan struct{})
	return &singleConnListener{conn: &closeNotifyConn{Conn: conn, done: done}, done: done}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	accepted := false
	l.once.Do(func() { accepted = true })
	if accepted {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
