package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func testEngineLog(message string) EngineLog {
	return EngineLog{
		Level: "info", Source: "engine", Extension: "io.example.fixture", Action: "action",
		Phase: "response", DurationMS: 1, URL: "https://api.example.com/", ScriptDigest: strings.Repeat("a", 64), Message: message,
	}
}

func nextEngineLog(t *testing.T, subscription *engineLogSubscription) EngineLog {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event EngineLog
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestEngineLogRingStartsAtTailAndDropsOldest(t *testing.T) {
	t.Parallel()
	hub := newEngineLogHub(3)
	hub.now = func() time.Time { return time.Date(2026, 7, 23, 1, 2, 3, 4, time.UTC) }
	hub.Publish(testEngineLog("before subscription"))
	subscription, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	for index := 0; index < 5; index++ {
		hub.Publish(testEngineLog(fmt.Sprintf("event-%d", index)))
	}
	for _, want := range []string{"event-2", "event-3", "event-4"} {
		if got := nextEngineLog(t, subscription); got.Message != want || got.Time != "2026-07-23T01:02:03.000000004Z" {
			t.Fatalf("event = %+v, want message %q", got, want)
		}
	}
}

func TestEngineLogPublishSkipsNormalizationAndAllocationWithoutSubscribers(t *testing.T) {
	hub := newEngineLogHub(3)
	var normalized atomic.Int32
	hub.now = func() time.Time {
		normalized.Add(1)
		return time.Now()
	}
	event := testEngineLog("not observed")
	if hub.Enabled() || hub.HasSubscribers() {
		t.Fatal("new engine log hub unexpectedly reported a subscriber")
	}
	if allocations := testing.AllocsPerRun(100, func() { hub.Publish(event) }); allocations != 0 {
		t.Fatalf("publish without subscribers allocated %.2f objects", allocations)
	}
	if normalized.Load() != 0 || hub.next != 0 {
		t.Fatalf("publish without subscribers normalized=%d next=%d", normalized.Load(), hub.next)
	}

	subscription, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	if !hub.Enabled() || !hub.HasSubscribers() {
		t.Fatal("subscribed engine log hub did not enable publishing")
	}
	hub.Publish(event)
	if normalized.Load() != 1 || hub.next != 1 {
		t.Fatalf("subscribed publish normalized=%d next=%d", normalized.Load(), hub.next)
	}
	subscription.Close()
	if hub.Enabled() || hub.HasSubscribers() {
		t.Fatal("closed final subscription left publishing enabled")
	}
}

func TestEngineLogSubscriberCountIsSafeUnderConcurrentClose(t *testing.T) {
	hub := newEngineLogHub(16)
	const workers = 64
	var subscriptions [workers]*engineLogSubscription
	for index := range subscriptions {
		subscription, err := hub.Subscribe()
		if err != nil {
			t.Fatal(err)
		}
		subscriptions[index] = subscription
	}
	if got := hub.subscribers.Load(); got != workers {
		t.Fatalf("subscriber count = %d, want %d", got, workers)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for _, subscription := range subscriptions {
		wait.Add(1)
		go func(subscription *engineLogSubscription) {
			defer wait.Done()
			<-start
			subscription.Close()
			subscription.Close()
		}(subscription)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		hub.Close()
	}()
	close(start)
	wait.Wait()
	if got := hub.subscribers.Load(); got != 0 || hub.HasSubscribers() {
		t.Fatalf("subscriber count after concurrent close = %d", got)
	}
	if _, err := hub.Subscribe(); err == nil {
		t.Fatal("closed hub accepted a new subscription")
	}
}

func TestEngineLogPublishNeverBlocksOnSlowConsumer(t *testing.T) {
	t.Parallel()
	hub := newEngineLogHub(4)
	subscription, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	done := make(chan struct{})
	go func() {
		for index := 0; index < 10000; index++ {
			hub.Publish(testEngineLog("message"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked behind a slow subscriber")
	}
}

func TestEngineLogJSONFieldsAndLimits(t *testing.T) {
	t.Parallel()
	hub := newEngineLogHub(1)
	subscription, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	event := testEngineLog(strings.Repeat("m", maxEngineLogMessageBytes+100))
	event.URL = "https://api.example.com/" + strings.Repeat("u", maxEngineLogURLBytes)
	hub.Publish(event)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 10 {
		t.Fatalf("JSON fields = %v", fields)
	}
	for _, name := range []string{"time", "level", "source", "extension", "action", "phase", "duration_ms", "url", "script_digest", "message"} {
		if _, exists := fields[name]; !exists {
			t.Fatalf("missing JSON field %q", name)
		}
	}
	if len(fields["message"].(string)) > maxEngineLogMessageBytes || len(fields["url"].(string)) > maxEngineLogURLBytes || len(payload) > maxEngineLogJSONBytes {
		t.Fatal("engine log exceeded its delivery bounds")
	}
	hub.Publish(EngineLog{Level: "info", Source: "engine", Message: "lifecycle"})
	payload, err = subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields = nil
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || fields["message"] != "lifecycle" {
		t.Fatalf("lifecycle JSON fields = %v", fields)
	}
}

func TestEngineLogTruncationBoundsInvalidUTF8Processing(t *testing.T) {
	t.Parallel()
	result := truncateEngineLogField(strings.Repeat("\xff", 1<<20), 64)
	if len(result) > 64 || !utf8.ValidString(result) {
		t.Fatalf("truncated invalid UTF-8 = %q", result)
	}
}

type recordingEngineLogPublisher struct {
	mu     sync.Mutex
	events []EngineLog
}

func (p *recordingEngineLogPublisher) Enabled() bool {
	return true
}

func (p *recordingEngineLogPublisher) Publish(event EngineLog) {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
}

func (p *recordingEngineLogPublisher) snapshot() []EngineLog {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]EngineLog(nil), p.events...)
}

func TestNativeConsolePublishesStructuredLevelsWithoutJournalLogging(t *testing.T) {
	t.Parallel()
	publisher := &recordingEngineLogPublisher{}
	runtime := newScriptRuntimeWithLogs(publisher)
	source := `function transform() {
  console.log("log")
  console.info("info")
  console.warn("warn")
  console.error("error\nline")
  return null
}`
	rule := nativeRuntimeRule(source, "response", "none")
	request := scriptMessage{URL: "https://api.example.com/path", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	if _, err := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response); err != nil {
		t.Fatal(err)
	}
	events := publisher.snapshot()
	if len(events) != 5 {
		t.Fatalf("events = %+v", events)
	}
	for index, level := range []string{"info", "info", "warn", "error"} {
		if events[index].Level != level || events[index].Source != "script" || events[index].Extension != "io.example.fixture" || events[index].Action != "action" {
			t.Fatalf("console event %d = %+v", index, events[index])
		}
	}
	if events[3].Message != `error\nline` {
		t.Fatalf("error console message = %q", events[3].Message)
	}
	if events[4].Source != "engine" || events[4].Message != "action completed" || events[4].DurationMS < 0 {
		t.Fatalf("completion event = %+v", events[4])
	}
}

func TestNativeConsoleSkipsArgumentFormattingWithoutSubscribers(t *testing.T) {
	t.Parallel()
	hub := newEngineLogHub(8)
	runtime := newScriptRuntimeWithLogs(hub)
	rule := nativeRuntimeRule(`function transform() {
  let formatted = 0
  console.log({toString() { formatted++; return "formatted" }})
  return {response: {body: String(formatted)}}
}`, "response", "text")
	message := scriptMessage{URL: "https://api.example.com/", StatusCode: http.StatusOK, Headers: make(http.Header)}
	result, err := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, message, &message)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "0" {
		t.Fatalf("unobserved console argument was formatted %q times", got)
	}

	subscription, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	result, err = runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, message, &message)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "1" {
		t.Fatalf("observed console argument was formatted %q times", got)
	}
	if event := nextEngineLog(t, subscription); event.Source != "script" || event.Message != "formatted" {
		t.Fatalf("console event = %+v", event)
	}
}

func TestNativeConsoleOutputIsBoundedPerAction(t *testing.T) {
	t.Parallel()
	publisher := &recordingEngineLogPublisher{}
	runtime := newScriptRuntimeWithLogs(publisher)
	rule := nativeRuntimeRule(`function transform() {
  for (let index = 0; index < 140; index++) console.log(index)
  return null
}`, "response", "none")
	message := scriptMessage{URL: "https://api.example.com/", StatusCode: 200, Headers: make(http.Header)}
	if _, err := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, message, &message); err != nil {
		t.Fatal(err)
	}
	events := publisher.snapshot()
	if len(events) != maxConsoleLogsPerAction+2 {
		t.Fatalf("bounded console events = %d", len(events))
	}
	if events[maxConsoleLogsPerAction].Level != "warn" || !strings.Contains(events[maxConsoleLogsPerAction].Message, "output limit") || events[len(events)-1].Message != "action completed" {
		t.Fatalf("console limit events = %+v", events[maxConsoleLogsPerAction:])
	}
}

func TestNativeConsoleArgumentsAndMessageBytesAreBounded(t *testing.T) {
	t.Parallel()
	publisher := &recordingEngineLogPublisher{}
	runtime := newScriptRuntimeWithLogs(publisher)
	rule := nativeRuntimeRule(`function transform() {
  console.log(...Array.from({length: 32}, () => "x".repeat(8192)))
  return null
}`, "response", "none")
	message := scriptMessage{URL: "https://api.example.com/", StatusCode: 200, Headers: make(http.Header)}
	if _, err := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, message, &message); err != nil {
		t.Fatal(err)
	}
	events := publisher.snapshot()
	if len(events) != 2 || len(events[0].Message) > maxEngineLogMessageBytes {
		t.Fatalf("bounded console events = %+v", events)
	}
}

func TestNativeExecutePublishesTimeoutAndSanitizedMetadata(t *testing.T) {
	t.Parallel()
	publisher := &recordingEngineLogPublisher{}
	runtime := newScriptRuntimeWithLogs(publisher)
	rule := nativeRuntimeRule(`function transform() { while (true) {} }`, "response", "none")
	rule.TimeoutMS = 50
	request := scriptMessage{
		URL: "https://user:pass@api.example.com/timeout?token=query-secret#fragment", Headers: http.Header{"Authorization": {"secret-header"}}, Body: []byte("secret-body"),
	}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	if _, err := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response); err == nil {
		t.Fatal("timed out action succeeded")
	}
	events := publisher.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	event := events[0]
	if event.Level != "warn" || event.Source != "engine" || event.Message != "action timed out" || event.Phase != "response" || event.URL != "https://api.example.com/timeout" || event.ScriptDigest != rule.ScriptDigest || event.DurationMS <= 0 {
		t.Fatalf("timeout event = %+v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret-header")) || bytes.Contains(encoded, []byte("secret-body")) || bytes.Contains(encoded, []byte("query-secret")) || bytes.Contains(encoded, []byte("user:pass")) {
		t.Fatal("engine event leaked request headers, body, or URL credentials")
	}
}

func TestEngineLogWebSocketRequestValidation(t *testing.T) {
	t.Parallel()
	valid := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "http://sidecar/logs", nil)
		request.Header.Set("Connection", "keep-alive, Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
		return request
	}
	if _, err := validateEngineLogWebSocketRequest(valid()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*http.Request){
		"query":   func(request *http.Request) { request.URL.RawQuery = "ticket=leak" },
		"version": func(request *http.Request) { request.Header.Set("Sec-WebSocket-Version", "12") },
		"key":     func(request *http.Request) { request.Header.Set("Sec-WebSocket-Key", "short") },
		"upgrade": func(request *http.Request) { request.Header.Del("Connection") },
		"body":    func(request *http.Request) { request.ContentLength = 1 },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			request := valid()
			mutate(request)
			if _, err := validateEngineLogWebSocketRequest(request); err == nil {
				t.Fatal("invalid websocket request was accepted")
			}
		})
	}
}

func TestEngineLogWebSocketStreamsTextAndHandlesClose(t *testing.T) {
	hub := newEngineLogHub(10)
	service := newEngineLogService(hub, nil, "test")
	server := httptest.NewServer(service)
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	if _, err := fmt.Fprintf(connection, "GET /logs HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", address, key); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != webSocketAccept(key) {
		t.Fatalf("upgrade response = %+v", response)
	}
	if err := writeMaskedClientFrame(connection, 0x9, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	opcode, payload, err := readServerWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0xA || string(payload) != "ping" {
		t.Fatalf("pong opcode=%d payload=%q", opcode, payload)
	}
	hub.Publish(testEngineLog("streamed"))
	opcode, payload, err = readServerWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x1 || !bytes.Contains(payload, []byte(`"message":"streamed"`)) {
		t.Fatalf("frame opcode=%d payload=%s", opcode, payload)
	}
	if err := writeMaskedClientFrame(connection, 0x8, webSocketClosePayload(1000, "")); err != nil {
		t.Fatal(err)
	}
	opcode, _, err = readServerWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x8 {
		t.Fatalf("close opcode = %d", opcode)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := readServerWebSocketFrame(reader); err == nil {
		t.Fatal("server sent a frame after its close response")
	}
}

func TestEngineLogWebSocketConcurrentPublishCompletesCloseBeforeDisconnect(t *testing.T) {
	hub := newEngineLogHub(100)
	service := newEngineLogService(hub, nil, "test")
	server := httptest.NewServer(service)
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	key := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	if _, err := fmt.Fprintf(connection, "GET /logs HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", address, key); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}

	startPublishing := make(chan struct{})
	published := make(chan struct{})
	go func() {
		defer close(published)
		<-startPublishing
		for index := 0; index < 5000; index++ {
			hub.Publish(testEngineLog(fmt.Sprintf("concurrent-%d", index)))
		}
	}()
	close(startPublishing)
	if err := writeMaskedClientFrame(connection, 0x8, webSocketClosePayload(1000, "client close")); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		opcode, _, err := readServerWebSocketFrame(reader)
		if err != nil {
			t.Fatalf("connection ended before close response: %v", err)
		}
		if opcode == 0x8 {
			break
		}
		if opcode != 0x1 {
			t.Fatalf("unexpected opcode before close = %d", opcode)
		}
	}
	if _, _, err := readServerWebSocketFrame(reader); err == nil {
		t.Fatal("server sent a frame after the close response")
	}
	select {
	case <-published:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent publisher blocked during websocket close")
	}
}

func TestEngineLogWebSocketFrameValidationAndCapacity(t *testing.T) {
	t.Parallel()
	maskedPing := maskedClientFrame(0x9, []byte("ping"))
	opcode, payload, err := readWebSocketClientFrame(bufio.NewReader(bytes.NewReader(maskedPing)))
	if err != nil || opcode != 0x9 || string(payload) != "ping" {
		t.Fatalf("ping opcode=%d payload=%q err=%v", opcode, payload, err)
	}
	if _, _, err := readWebSocketClientFrame(bufio.NewReader(bytes.NewReader([]byte{0x89, 0x00}))); err == nil {
		t.Fatal("unmasked client frame was accepted")
	}
	oversized := []byte{0x81, 0xFE, 0x10, 0x01}
	if _, _, err := readWebSocketClientFrame(bufio.NewReader(bytes.NewReader(oversized))); err == nil {
		t.Fatal("oversized client frame was accepted")
	}
	if _, _, err := readWebSocketClientFrame(bufio.NewReader(bytes.NewReader(maskedClientFrame(0x8, webSocketClosePayload(1005, ""))))); err == nil {
		t.Fatal("reserved websocket close code was accepted")
	}

	service := newEngineLogService(newEngineLogHub(10), nil, "test")
	wrongVersion := httptest.NewRequest(http.MethodGet, "http://sidecar/logs", nil)
	wrongVersion.Header.Set("Connection", "Upgrade")
	wrongVersion.Header.Set("Upgrade", "websocket")
	wrongVersion.Header.Set("Sec-WebSocket-Version", "12")
	wrongVersion.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	versionRecorder := httptest.NewRecorder()
	service.ServeHTTP(versionRecorder, wrongVersion)
	if versionRecorder.Code != http.StatusUpgradeRequired || versionRecorder.Header().Get("Sec-WebSocket-Version") != "13" {
		t.Fatalf("version response = status %d headers %v", versionRecorder.Code, versionRecorder.Header())
	}
	for index := 0; index < maxEngineLogWebSockets; index++ {
		service.slots <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodGet, "http://sidecar/logs", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d", recorder.Code)
	}
}

func TestEngineLogHealthReportsActiveExtensions(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service := newEngineLogService(newEngineLogHub(10), store, "1.2.3")
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://sidecar/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health status = %d", recorder.Code)
	}
	var health engineLogHealth
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if !health.Running || health.ActiveExtensions != 1 || health.Version != "1.2.3" {
		t.Fatalf("health = %+v", health)
	}
}

func TestEngineLogServiceContextClosesHubAndListener(t *testing.T) {
	t.Parallel()
	hub := newEngineLogHub(10)
	service := newEngineLogService(hub, nil, "test")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service.listener = listener
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("engine log service did not stop with its context")
	}
	if _, err := hub.Subscribe(); err == nil {
		t.Fatal("engine log hub remained open after service shutdown")
	}
}

func TestConfigStorePublishesEngineLifecycleEvents(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	baseTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	writeConfigAt(t, path, body, baseTime)
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &recordingEngineLogPublisher{}
	store.setEngineLogPublisher(publisher)

	cfg.MITM.HTTP2 = false
	changed, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeConfigAt(t, path, changed, baseTime.Add(time.Second))
	if _, err := store.Current(); err != nil {
		t.Fatal(err)
	}
	writeConfigAt(t, path, []byte("{"), baseTime.Add(2*time.Second))
	if _, err := store.Current(); err != nil {
		t.Fatal(err)
	}
	events := publisher.snapshot()
	if len(events) != 2 || events[0].Level != "info" || events[0].Message != "configuration reloaded" || events[1].Level != "error" || !strings.Contains(events[1].Message, "configuration replacement rejected") {
		t.Fatalf("lifecycle events = %+v", events)
	}
}

type observedEngineLogError struct {
	calls atomic.Int32
}

func (e *observedEngineLogError) Error() string {
	e.calls.Add(1)
	return "observed read failure"
}

func TestConfigStoreSkipsLifecycleErrorFormattingWithoutSubscribers(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	baseTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	writeConfigAt(t, path, body, baseTime)
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	hub := newEngineLogHub(4)
	store.setEngineLogPublisher(hub)
	cfg.MITM.HTTP2 = false
	changed, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeConfigAt(t, path, changed, baseTime.Add(time.Second))
	observed := &observedEngineLogError{}
	store.readDocument = func(string) ([]byte, os.FileInfo, error) {
		return nil, nil, observed
	}
	if _, err := store.Current(); err != nil {
		t.Fatal(err)
	}
	if calls := observed.calls.Load(); calls != 0 {
		t.Fatalf("disabled lifecycle logging formatted the read error %d times", calls)
	}
}

var benchmarkEngineLogActionResult scriptResult

func BenchmarkNativeActionEngineLogging(b *testing.B) {
	source := `function transform() { return null }`
	rule := nativeRuntimeRule(source, "response", "none")
	program, err := scriptProgram(nativeRuntimeModule(), rule)
	if err != nil {
		b.Fatal(err)
	}
	rule.program = program
	rule.settings = map[string]any{}
	request := scriptMessage{URL: "https://api.example.com/data?secret=value", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, Method: request.Method, StatusCode: http.StatusOK, Headers: make(http.Header)}
	for _, test := range []struct {
		name       string
		subscribed bool
	}{
		{name: "no-subscriber"},
		{name: "subscriber", subscribed: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			hub := newEngineLogHub(engineLogRingCapacity)
			if test.subscribed {
				subscription, subscribeErr := hub.Subscribe()
				if subscribeErr != nil {
					b.Fatal(subscribeErr)
				}
				b.Cleanup(subscription.Close)
			}
			runtime := newScriptRuntimeWithLogs(hub)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				result, executeErr := runtime.execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response)
				if executeErr != nil {
					b.Fatal(executeErr)
				}
				benchmarkEngineLogActionResult = result
			}
		})
	}
}

func TestEngineLogUnixSocketPathSafetyAndMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket filesystem semantics are unavailable on Windows")
	}
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.sock")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleEngineLogsSocket(regular); err == nil {
		t.Fatal("regular file at socket path was removed")
	}
	if body, err := os.ReadFile(regular); err != nil || string(body) != "keep" {
		t.Fatal("regular file at socket path was changed")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.sock")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := removeStaleEngineLogsSocket(symlink); err == nil {
		t.Fatal("symlink at socket path was removed")
	}
	activePath := filepath.Join(dir, "already-active.sock")
	activeListener, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeStaleEngineLogsSocket(activePath); err == nil {
		activeListener.Close()
		t.Fatal("active Unix socket was removed as stale")
	}
	if err := activeListener.Close(); err != nil {
		t.Fatal(err)
	}

	stale := filepath.Join(dir, "stale.sock")
	listener, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleEngineLogsSocket(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale Unix socket was not removed")
	}

	active := filepath.Join(dir, "active.sock")
	listener, err = listenEngineLogsSocketAt(active)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if duplicate, err := listenEngineLogsSocketAt(active); err == nil {
		duplicate.Close()
		t.Fatal("second engine log listener acquired the active runtime lock")
	}
	info, err := os.Stat(active)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v", info.Mode())
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(active + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("engine log listener lock survived a graceful close")
	}
}

func maskedClientFrame(opcode byte, payload []byte) []byte {
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for index, item := range payload {
		frame = append(frame, item^mask[index%len(mask)])
	}
	return frame
}

func writeMaskedClientFrame(writer io.Writer, opcode byte, payload []byte) error {
	_, err := writer.Write(maskedClientFrame(opcode, payload))
	return err
}

func readServerWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if first&0x80 == 0 || second&0x80 != 0 {
		return 0, nil, errors.New("invalid server websocket frame")
	}
	length := uint64(second & 0x7f)
	if length == 126 {
		var encoded [2]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(encoded[:]))
	} else if length == 127 {
		var encoded [8]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(encoded[:])
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return first & 0x0f, payload, nil
}
