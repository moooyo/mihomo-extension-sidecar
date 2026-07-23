package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	engineLogsSocketPath          = "/run/5gpn-intercept/logs.sock"
	engineLogRingCapacity         = 1000
	maxEngineLogWebSockets        = 8
	maxEngineLogMessageBytes      = 2048
	maxEngineLogURLBytes          = 4096
	maxEngineLogJSONBytes         = 8 << 10
	maxWebSocketClientFrameBytes  = 4 << 10
	maxWebSocketServerFrameBytes  = 16 << 10
	engineLogWebSocketPingPeriod  = 30 * time.Second
	engineLogWebSocketPongTimeout = 60 * time.Second
	engineLogWebSocketWriteWait   = 10 * time.Second
	engineLogWebSocketCloseWait   = time.Second
)

var errEngineLogWebSocketVersion = errors.New("unsupported websocket version")

type EngineLog struct {
	Time         string  `json:"time"`
	Level        string  `json:"level"`
	Source       string  `json:"source"`
	Extension    string  `json:"extension,omitempty"`
	Action       string  `json:"action,omitempty"`
	Phase        string  `json:"phase,omitempty"`
	DurationMS   float64 `json:"duration_ms,omitempty"`
	URL          string  `json:"url,omitempty"`
	ScriptDigest string  `json:"script_digest,omitempty"`
	Message      string  `json:"message"`
}

type engineLogPublisher interface {
	Enabled() bool
	Publish(EngineLog)
}

func engineLogPublishingEnabled(publisher engineLogPublisher) bool {
	return publisher != nil && publisher.Enabled()
}

type engineLogHub struct {
	mu          sync.Mutex
	ring        [][]byte
	next        uint64
	closed      bool
	now         func() time.Time
	readers     map[*engineLogSubscription]struct{}
	subscribers atomic.Int32
}

type engineLogSubscription struct {
	hub    *engineLogHub
	cursor uint64
	wake   chan struct{}
	closed bool
}

func newEngineLogHub(capacity int) *engineLogHub {
	if capacity <= 0 || capacity > engineLogRingCapacity {
		capacity = engineLogRingCapacity
	}
	return &engineLogHub{
		ring:    make([][]byte, capacity),
		now:     time.Now,
		readers: make(map[*engineLogSubscription]struct{}),
	}
}

func (h *engineLogHub) Enabled() bool {
	return h.HasSubscribers()
}

func (h *engineLogHub) HasSubscribers() bool {
	return h != nil && h.subscribers.Load() > 0
}

func (h *engineLogHub) Publish(event EngineLog) {
	if !h.HasSubscribers() {
		return
	}
	h.mu.Lock()
	if h.closed || h.subscribers.Load() == 0 {
		h.mu.Unlock()
		return
	}
	now := h.now
	h.mu.Unlock()

	normalized, err := normalizeEngineLog(event, now().UTC())
	if err != nil {
		return
	}
	payload, err := json.Marshal(normalized)
	if err != nil || len(payload) > maxEngineLogJSONBytes {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	sequence := h.next
	h.ring[sequence%uint64(len(h.ring))] = payload
	h.next++
	for reader := range h.readers {
		select {
		case reader.wake <- struct{}{}:
		default:
		}
	}
}

func normalizeEngineLog(event EngineLog, now time.Time) (EngineLog, error) {
	switch event.Level {
	case "info", "warn", "error":
	default:
		return EngineLog{}, errors.New("invalid engine log level")
	}
	switch event.Source {
	case "script", "engine":
	default:
		return EngineLog{}, errors.New("invalid engine log source")
	}
	if event.Extension != "" && !validModuleID(event.Extension) {
		return EngineLog{}, errors.New("invalid engine log extension")
	}
	if event.Action != "" && !validSettingKey(event.Action) {
		return EngineLog{}, errors.New("invalid engine log action")
	}
	if event.Source == "script" && (event.Extension == "" || event.Action == "") {
		return EngineLog{}, errors.New("script log is missing its extension or action")
	}
	if event.Phase != "" && event.Phase != "request" && event.Phase != "response" {
		return EngineLog{}, errors.New("invalid engine log phase")
	}
	if event.ScriptDigest != "" && !validEngineLogDigest(event.ScriptDigest) {
		return EngineLog{}, errors.New("invalid engine log script digest")
	}
	if math.IsNaN(event.DurationMS) || math.IsInf(event.DurationMS, 0) || event.DurationMS < 0 {
		return EngineLog{}, errors.New("invalid engine log duration")
	}
	if event.DurationMS > 300000 {
		event.DurationMS = 300000
	}
	event.Time = now.Format(time.RFC3339Nano)
	event.URL = sanitizeEngineLogURL(event.URL)
	event.Message = truncateEngineLogField(event.Message, maxEngineLogMessageBytes)
	return event, nil
}

func sanitizeEngineLogURL(raw string) string {
	if raw == "" {
		return ""
	}
	raw = truncateEngineLogField(raw, maxEngineLogURLBytes)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return truncateEngineLogField(parsed.String(), maxEngineLogURLBytes)
}

func validEngineLogDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, item := range value {
		if (item < '0' || item > '9') && (item < 'a' || item > 'f') {
			return false
		}
	}
	return true
}

func truncateEngineLogField(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	truncated := len(value) > limit
	if truncated && limit <= 3 {
		return strings.Repeat(".", limit)
	}
	budget := limit
	if truncated {
		budget -= 3
	}
	if len(value) > budget {
		value = value[:budget]
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) > budget {
		value = value[:budget]
	}
	prefix := value
	for len(prefix) > 0 && !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	if truncated {
		return prefix + "..."
	}
	return prefix
}

func (h *engineLogHub) Subscribe() (*engineLogSubscription, error) {
	if h == nil {
		return nil, errors.New("engine log hub is unavailable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("engine log hub is closed")
	}
	subscription := &engineLogSubscription{hub: h, cursor: h.next, wake: make(chan struct{}, 1)}
	h.readers[subscription] = struct{}{}
	h.subscribers.Add(1)
	return subscription, nil
}

func (s *engineLogSubscription) Next(ctx context.Context) ([]byte, error) {
	if s == nil || s.hub == nil {
		return nil, errors.New("engine log subscription is unavailable")
	}
	for {
		h := s.hub
		h.mu.Lock()
		if s.closed || h.closed {
			h.mu.Unlock()
			return nil, io.EOF
		}
		oldest := uint64(0)
		if h.next > uint64(len(h.ring)) {
			oldest = h.next - uint64(len(h.ring))
		}
		if s.cursor < oldest {
			s.cursor = oldest
		}
		if s.cursor < h.next {
			payload := h.ring[s.cursor%uint64(len(h.ring))]
			s.cursor++
			h.mu.Unlock()
			return payload, nil
		}
		wake := s.wake
		h.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case _, ok := <-wake:
			if !ok {
				return nil, io.EOF
			}
		}
	}
}

func (s *engineLogSubscription) Close() {
	if s == nil || s.hub == nil {
		return
	}
	h := s.hub
	h.mu.Lock()
	if !s.closed {
		s.closed = true
		delete(h.readers, s)
		h.subscribers.Add(-1)
		close(s.wake)
	}
	h.mu.Unlock()
}

func (h *engineLogHub) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		for reader := range h.readers {
			reader.closed = true
			close(reader.wake)
			delete(h.readers, reader)
		}
		h.subscribers.Store(0)
	}
	h.mu.Unlock()
}

type engineLogService struct {
	hub      *engineLogHub
	config   *configStore
	version  string
	slots    chan struct{}
	listener net.Listener
	server   *http.Server
	close    sync.Once
}

type engineLogHealth struct {
	Running          bool   `json:"running"`
	ActiveExtensions int    `json:"active_extensions"`
	Version          string `json:"version"`
}

func newEngineLogService(hub *engineLogHub, config *configStore, version string) *engineLogService {
	service := &engineLogService{
		hub: hub, config: config, version: version, slots: make(chan struct{}, maxEngineLogWebSockets),
	}
	service.server = &http.Server{
		Handler:           service,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return service
}

func startEngineLogService(hub *engineLogHub, config *configStore, version string) (*engineLogService, error) {
	listener, err := listenEngineLogsSocket()
	if err != nil {
		return nil, err
	}
	service := newEngineLogService(hub, config, version)
	service.listener = listener
	return service, nil
}

func (s *engineLogService) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil {
		return errors.New("engine log listener is unavailable")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-done:
		}
	}()
	err := s.server.Serve(s.listener)
	close(done)
	s.Close()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *engineLogService) Close() {
	if s == nil {
		return
	}
	s.close.Do(func() {
		_ = s.server.Close()
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.hub.Close()
	})
}

func (s *engineLogService) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/health":
		s.serveHealth(w, request)
	case "/logs":
		s.serveLogs(w, request)
	default:
		http.NotFound(w, request)
	}
}

func (s *engineLogService) serveHealth(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		http.Error(w, "method or query not permitted", http.StatusMethodNotAllowed)
		return
	}
	health := engineLogHealth{Running: true, Version: s.version}
	status := http.StatusOK
	if s.config == nil {
		status = http.StatusServiceUnavailable
	} else if cfg, err := s.config.Current(); err != nil {
		status = http.StatusServiceUnavailable
	} else {
		health.ActiveExtensions = activeExtensionCount(cfg)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(health)
}

func activeExtensionCount(cfg Config) int {
	if !cfg.MITM.Enabled {
		return 0
	}
	count := 0
	for _, module := range cfg.Modules {
		if module.Enabled {
			count++
		}
	}
	return count
}

func (s *engineLogService) serveLogs(w http.ResponseWriter, request *http.Request) {
	key, err := validateEngineLogWebSocketRequest(request)
	if err != nil {
		if errors.Is(err, errEngineLogWebSocketVersion) {
			w.Header().Set("Sec-WebSocket-Version", "13")
			http.Error(w, err.Error(), http.StatusUpgradeRequired)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "engine log websocket capacity is busy", http.StatusServiceUnavailable)
		return
	}
	subscription, err := s.hub.Subscribe()
	if err != nil {
		http.Error(w, "engine log stream is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer subscription.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket upgrade is unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	accept := webSocketAccept(key)
	if _, err := fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	serveEngineLogWebSocket(request.Context(), connection, buffered, subscription)
}

func validateEngineLogWebSocketRequest(request *http.Request) (string, error) {
	if request.Method != http.MethodGet || request.ProtoMajor != 1 || request.ProtoMinor < 1 {
		return "", errors.New("websocket requires HTTP/1.1 GET")
	}
	hasBody := request.Body != nil && request.Body != http.NoBody
	if request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) > 0 || hasBody {
		return "", errors.New("websocket query or body is not permitted")
	}
	if !headerContainsToken(request.Header.Values("Connection"), "upgrade") {
		return "", errors.New("missing websocket connection upgrade")
	}
	upgrades := request.Header.Values("Upgrade")
	if len(upgrades) != 1 || !strings.EqualFold(strings.TrimSpace(upgrades[0]), "websocket") {
		return "", errors.New("invalid websocket upgrade")
	}
	versions := request.Header.Values("Sec-WebSocket-Version")
	if len(versions) != 1 || strings.TrimSpace(versions[0]) != "13" {
		return "", errEngineLogWebSocketVersion
	}
	keys := request.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return "", errors.New("invalid websocket key")
	}
	key := strings.TrimSpace(keys[0])
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 || base64.StdEncoding.EncodeToString(decoded) != key {
		return "", errors.New("invalid websocket key")
	}
	return key, nil
}

func headerContainsToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func serveEngineLogWebSocket(parent context.Context, connection net.Conn, buffered *bufio.ReadWriter, subscription *engineLogSubscription) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var writeMu sync.Mutex
	var closing atomic.Bool
	closeWriteDone := make(chan struct{})
	var closeWriteOnce sync.Once
	defer func() {
		if !closing.Load() {
			return
		}
		timer := time.NewTimer(engineLogWebSocketCloseWait + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-closeWriteDone:
		case <-timer.C:
		}
	}()
	writeFrame := func(opcode byte, payload []byte) error {
		if opcode == 0x8 {
			if !closing.CompareAndSwap(false, true) {
				return net.ErrClosed
			}
			defer closeWriteOnce.Do(func() { close(closeWriteDone) })
		} else if closing.Load() {
			return net.ErrClosed
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if opcode != 0x8 && closing.Load() {
			return net.ErrClosed
		}
		writeWait := engineLogWebSocketWriteWait
		if opcode == 0x8 {
			writeWait = engineLogWebSocketCloseWait
		}
		_ = connection.SetWriteDeadline(time.Now().Add(writeWait))
		return writeWebSocketFrame(buffered.Writer, opcode, payload)
	}
	_ = connection.SetReadDeadline(time.Now().Add(engineLogWebSocketPongTimeout))
	go func() {
		for {
			opcode, payload, err := readWebSocketClientFrame(buffered.Reader)
			if err != nil {
				_ = writeFrame(0x8, webSocketClosePayload(1002, "protocol error"))
				cancel()
				return
			}
			switch opcode {
			case 0x8:
				_ = writeFrame(0x8, payload)
				cancel()
				return
			case 0x9:
				if err := writeFrame(0xA, payload); err != nil {
					cancel()
					return
				}
			case 0xA:
				_ = connection.SetReadDeadline(time.Now().Add(engineLogWebSocketPongTimeout))
			default:
				_ = writeFrame(0x8, webSocketClosePayload(1003, "read-only stream"))
				cancel()
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(engineLogWebSocketPingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := writeFrame(0x9, nil); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		payload, err := subscription.Next(ctx)
		if err != nil {
			return
		}
		if len(payload) > maxWebSocketServerFrameBytes || writeFrame(0x1, payload) != nil {
			return
		}
	}
}

func readWebSocketClientFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if first&0x70 != 0 || first&0x80 == 0 || second&0x80 == 0 {
		return 0, nil, errors.New("invalid websocket frame flags")
	}
	opcode := first & 0x0f
	if opcode != 0x1 && opcode != 0x2 && opcode != 0x8 && opcode != 0x9 && opcode != 0xA {
		return 0, nil, errors.New("unsupported websocket opcode")
	}
	length := uint64(second & 0x7f)
	switch length {
	case 126:
		var encoded [2]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(encoded[:]))
		if length < 126 {
			return 0, nil, errors.New("non-canonical websocket length")
		}
	case 127:
		var encoded [8]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(encoded[:])
		if length <= math.MaxUint16 || length>>63 != 0 {
			return 0, nil, errors.New("non-canonical websocket length")
		}
	}
	if opcode >= 0x8 && length > 125 {
		return 0, nil, errors.New("oversized websocket control frame")
	}
	if length > maxWebSocketClientFrameBytes {
		return 0, nil, errors.New("oversized websocket frame")
	}
	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	for index := range payload {
		payload[index] ^= mask[index%len(mask)]
	}
	if opcode == 0x8 {
		if len(payload) == 1 || len(payload) > 2 && !utf8.Valid(payload[2:]) {
			return 0, nil, errors.New("invalid websocket close payload")
		}
		if len(payload) >= 2 && !validWebSocketCloseCode(binary.BigEndian.Uint16(payload[:2])) {
			return 0, nil, errors.New("invalid websocket close code")
		}
	}
	return opcode, payload, nil
}

func validWebSocketCloseCode(code uint16) bool {
	if code >= 3000 && code <= 4999 {
		return true
	}
	if code < 1000 || code > 1014 {
		return false
	}
	return code != 1004 && code != 1005 && code != 1006
}

func writeWebSocketFrame(writer *bufio.Writer, opcode byte, payload []byte) error {
	if opcode >= 0x8 && len(payload) > 125 {
		return errors.New("oversized websocket control frame")
	}
	if len(payload) > maxWebSocketServerFrameBytes {
		return errors.New("oversized websocket server frame")
	}
	if err := writer.WriteByte(0x80 | opcode); err != nil {
		return err
	}
	switch {
	case len(payload) < 126:
		if err := writer.WriteByte(byte(len(payload))); err != nil {
			return err
		}
	case len(payload) <= math.MaxUint16:
		if err := writer.WriteByte(126); err != nil {
			return err
		}
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], uint16(len(payload)))
		if _, err := writer.Write(encoded[:]); err != nil {
			return err
		}
	default:
		if err := writer.WriteByte(127); err != nil {
			return err
		}
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(len(payload)))
		if _, err := writer.Write(encoded[:]); err != nil {
			return err
		}
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}

func webSocketClosePayload(code uint16, reason string) []byte {
	reason = truncateEngineLogField(reason, 123)
	payload := make([]byte, 2, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	return append(payload, reason...)
}

func listenEngineLogsSocket() (net.Listener, error) {
	return listenEngineLogsSocketAt(engineLogsSocketPath)
}

func listenEngineLogsSocketAt(path string) (net.Listener, error) {
	lockPath := path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("engine log socket lock is already held")
	}
	lockInfo, err := lockFile.Stat()
	if err != nil {
		lockFile.Close()
		_ = os.Remove(lockPath)
		return nil, err
	}
	releaseLock := func() {
		_ = lockFile.Close()
		current, statErr := os.Lstat(lockPath)
		if statErr == nil && current.Mode().IsRegular() && os.SameFile(lockInfo, current) {
			_ = os.Remove(lockPath)
		}
	}
	if err := removeStaleEngineLogsSocket(path); err != nil {
		releaseLock()
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		releaseLock()
		return nil, err
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		releaseLock()
		return nil, err
	}
	return &engineLogsLockedListener{Listener: listener, lockPath: lockPath, lockFile: lockFile, lockInfo: lockInfo}, nil
}

type engineLogsLockedListener struct {
	net.Listener
	lockPath string
	lockFile *os.File
	lockInfo os.FileInfo
	close    sync.Once
	err      error
}

func (l *engineLogsLockedListener) Close() error {
	l.close.Do(func() {
		l.err = l.Listener.Close()
		_ = l.lockFile.Close()
		current, err := os.Lstat(l.lockPath)
		if err == nil && current.Mode().IsRegular() && os.SameFile(l.lockInfo, current) {
			_ = os.Remove(l.lockPath)
		}
	})
	return l.err
}

func removeStaleEngineLogsSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("engine log socket path exists and is not a Unix socket")
	}
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("engine log socket path is already active")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		if errors.Is(dialErr, os.ErrNotExist) {
			return nil
		}
		return errors.New("could not verify that engine log socket is stale")
	}
	if !os.SameFile(info, info) {
		return errors.New("could not establish stale engine log socket identity")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(info, current) {
		return errors.New("engine log socket path changed before removal")
	}
	return os.Remove(path)
}
