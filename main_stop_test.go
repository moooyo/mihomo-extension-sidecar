package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A cold start must not act on a durable bundle that is older than the file
// systemd's --check-enabled just approved.
//
// Turning the MITM master off and back on is exactly that shape. Off stops this
// service, so the store's pointer names a disabled bundle. On writes the
// document, the path unit starts this process, and the coordinator pushes the
// enabled bundle a moment later -- but the runtime adopted the stale pointer
// first and stopped within about 460 ms, racing the commit. Observed on a real
// gateway: the commit landed on one run and was lost to the exit on the next,
// leaving the document saying enabled, the console reporting
// expected-but-not-running, and only `systemctl start` able to recover it.
func TestStopWhenMITMDisabledWaitsForTheCoordinatorAtStartup(t *testing.T) {
	t.Parallel()
	store := disabledConfigStoreForStopTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go stopWhenMITMDisabled(ctx, store, func() { close(stopped) }, 2*time.Second)

	select {
	case <-stopped:
		t.Fatal("stopped on a stale bundle before the coordinator could publish; the master switch becomes a one-way door")
	case <-time.After(700 * time.Millisecond):
	}

	// The grace is finite: a coordinator that never publishes still lets the
	// service stop rather than lingering forever.
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the startup grace never expired")
	}
}

// Once an active configuration has been observed, the master really was turned
// off while running, which is what this loop is for. It must stop promptly, and
// not sit through the startup grace.
func TestStopWhenMITMDisabledStopsPromptlyAfterAnActiveConfig(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	active := validNativeConfig()
	writeStopTestConfig(t, path, active)
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	// A long grace, so a pass can only come from having observed an active
	// configuration rather than from the deadline expiring.
	go stopWhenMITMDisabled(ctx, store, func() { close(stopped) }, time.Hour)

	// Let it observe the active configuration first.
	time.Sleep(600 * time.Millisecond)
	select {
	case <-stopped:
		t.Fatal("stopped while an extension was active")
	default:
	}

	disabled := active
	disabled.MITM.Enabled = false
	writeStopTestConfig(t, path, disabled)

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after the master was turned off while running")
	}
}

func disabledConfigStoreForStopTest(t *testing.T) *configStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := validNativeConfig()
	cfg.MITM.Enabled = false
	writeStopTestConfig(t, path, cfg)
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func writeStopTestConfig(t *testing.T, path string, cfg Config) {
	t.Helper()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// The store keys its reload on file identity and metadata, so a rewrite
	// inside one clock tick has to look different to be noticed.
	stamp := time.Now().Add(time.Duration(-1) * time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}
