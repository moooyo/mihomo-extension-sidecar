package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestTLSHandshakeErrorReporterPublishesRateLimitedTrustGuidance(t *testing.T) {
	var output bytes.Buffer
	publisher := &recordingEngineLogPublisher{}
	current := time.Date(2026, time.July, 24, 0, 0, 0, 0, time.UTC)
	reporter := newTLSHandshakeErrorReporter()
	reporter.logger = log.New(&output, "", 0)
	reporter.logs = publisher
	reporter.now = func() time.Time { return current }
	writer := reporter.writer("youtubei.googleapis.com")

	if _, err := writer.Write([]byte("http: TLS handshake error from 127.0.0.1:1234: EOF\n")); err != nil {
		t.Fatal(err)
	}
	if events := publisher.snapshot(); len(events) != 0 {
		t.Fatalf("ordinary TLS EOF published trust guidance: %+v", events)
	}

	unknownCertificate := []byte("http: TLS handshake error from 127.0.0.1:1234: remote error: tls: unknown certificate\n")
	if _, err := writer.Write(unknownCertificate); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(unknownCertificate); err != nil {
		t.Fatal(err)
	}
	events := publisher.snapshot()
	if len(events) != 1 {
		t.Fatalf("trust guidance events=%d, want 1", len(events))
	}
	if event := events[0]; event.Level != "warn" || event.Source != "engine" || event.URL != "https://youtubei.googleapis.com" || event.Message != interceptCertificateTrustMessage {
		t.Fatalf("trust guidance event=%+v", event)
	}
	if !strings.Contains(output.String(), `target="youtubei.googleapis.com"`) || !strings.Contains(output.String(), interceptCertificateTrustMessage) {
		t.Fatalf("journal diagnostic missing target or guidance: %q", output.String())
	}
	if count := strings.Count(output.String(), interceptCertificateTrustMessage); count != 1 {
		t.Fatalf("rate-limited journal guidance count=%d, want 1", count)
	}

	current = current.Add(interceptCertificateTrustLogInterval)
	if _, err := writer.Write(unknownCertificate); err != nil {
		t.Fatal(err)
	}
	if events := publisher.snapshot(); len(events) != 2 {
		t.Fatalf("trust guidance events after interval=%d, want 2", len(events))
	}
	if count := strings.Count(output.String(), interceptCertificateTrustMessage); count != 2 {
		t.Fatalf("journal guidance count after interval=%d, want 2", count)
	}
}
