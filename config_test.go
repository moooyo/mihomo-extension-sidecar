package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigStrictAndValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "version": 2,
  "listen": "127.0.0.1:18080",
  "username": "inbound-user-123",
  "password": "inbound-password-123456789",
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "upstream_proxy": {
    "address": "127.0.0.1:17890",
    "username": "upstream-user-123",
    "password": "upstream-password-12345678"
  },
  "mitm": {"enabled":true,"http2":true,"quic_fallback_protection":false},
  "wloc": {
    "enabled": true,
    "longitude": 113.9,
    "latitude": 22.5,
    "accuracy": 25,
    "fail_closed": true,
    "max_body_bytes": 8388608
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.MITM.Enabled || !cfg.MITM.HTTP2 || cfg.MITM.QUICFallbackProtection || !cfg.WLOC.Enabled || cfg.WLOC.Longitude == nil || *cfg.WLOC.Longitude != 113.9 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnknownAndNonLoopback(t *testing.T) {
	t.Parallel()
	base := `{
  "version": 2,
  "listen": %q,
  "username": "inbound-user-123",
  "password": "inbound-password-123456789",
  "tls_cert": "cert.pem",
  "tls_key": "key.pem",
  "upstream_proxy": {
    "address": "127.0.0.1:17890",
    "username": "upstream-user-123",
    "password": "upstream-password-12345678"
  },
  "mitm": {"enabled":false,"http2":true,"quic_fallback_protection":true},
  "wloc": {
    "enabled": false,
    "longitude": null,
    "latitude": null,
    "accuracy": 25,
    "fail_closed": true,
    "max_body_bytes": 8388608
  }%s
}`
	for _, tc := range []struct {
		name   string
		listen string
		extra  string
	}{
		{name: "public listener", listen: "0.0.0.0:18080"},
		{name: "unknown field", listen: "127.0.0.1:18080", extra: `, "unknown": true`},
		{name: "duplicate field", listen: "127.0.0.1:18080", extra: `, "Version": 1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := []byte(sprintf(base, tc.listen, tc.extra))
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("loadConfig accepted invalid config")
			}
		})
	}
}

func TestConfigStoreRetainsLastValidSnapshot(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	valid := `{
  "version": 2,
  "listen": "127.0.0.1:18080",
  "username": "inbound-user-123",
  "password": "inbound-password-123456789",
  "tls_cert": "cert.pem",
  "tls_key": "key.pem",
  "upstream_proxy": {"address":"127.0.0.1:17890","username":"upstream-user-123","password":"upstream-password-12345678"},
  "mitm": {"enabled":false,"http2":true,"quic_fallback_protection":true},
  "wloc": {"enabled":false,"longitude":null,"latitude":null,"accuracy":25,"fail_closed":true,"max_body_bytes":8388608}
}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Current()
	if err != nil {
		t.Fatalf("Current returned an error instead of the last valid snapshot: %v", err)
	}
	if cfg.Version != 2 || cfg.Listen != "127.0.0.1:18080" {
		t.Fatalf("Current returned the invalid replacement: %+v", cfg)
	}
}

func TestConfigValidatesImmutableModuleSnapshotsAndJavaScript(t *testing.T) {
	t.Parallel()
	longitude, latitude := 113.9, 22.5
	source := "#!name=Fixture\n"
	script := `$done({body: $response.body});`
	cfg := Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: "/etc/5gpn/intercept/tls/fullchain.pem", TLSKey: "/etc/5gpn/intercept/tls/privkey.pem",
		UpstreamProxy: ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		WLOC:          WLOCSettings{Longitude: &longitude, Latitude: &latitude, Accuracy: 25, FailClosed: true, MaxBodyBytes: 8 << 20},
		Modules: []Module{{
			ID: "mod-1234567890abcdef", Name: "Fixture", ImportedAt: time.Now().UTC().Format(time.RFC3339),
			Source: ModuleSource{Digest: digestText(source), Body: source}, Hosts: []string{"api.example.com"},
			Scripts: []ScriptRule{{ID: "script-001", Phase: "response", Pattern: `^https://api\.example\.com/`, ScriptURL: "https://modules.example.test/script.js", ScriptDigest: digestText(script), ScriptBody: script, TimeoutMS: 1000, MaxBodyBytes: 1 << 20}},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Modules[0].Scripts[0].ScriptBody = `function (`
	cfg.Modules[0].Scripts[0].ScriptDigest = digestText(cfg.Modules[0].Scripts[0].ScriptBody)
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid JavaScript snapshot was accepted")
	}
}

func TestConfigBlocksUnconfiguredOrUnsafeEnabledModule(t *testing.T) {
	t.Parallel()
	source := "#!name=Fixture\n"
	script := `$done({});`
	module := Module{
		ID: "mod-1234567890abcdef", Name: "Fixture", Enabled: true,
		ImportedAt: time.Now().UTC().Format(time.RFC3339),
		Source:     ModuleSource{Digest: digestText(source), Body: source},
		Hosts:      []string{"api.example.com"},
		Parameters: []ModuleParameter{{Key: "mode", Kind: "select", Options: []string{"clean", "full"}}},
		Scripts:    []ScriptRule{{ID: "script-001", Phase: "response", Pattern: `^https://api\.example\.com/`, ScriptURL: "https://modules.example.test/script.js", ScriptDigest: digestText(script), ScriptBody: script, TimeoutMS: 1000, MaxBodyBytes: 1 << 20}},
	}
	cfg := Config{Modules: []Module{module}}
	if err := validateModules(cfg.Modules); err == nil || !strings.Contains(err.Error(), "parameters") {
		t.Fatalf("unconfigured module error = %v", err)
	}
	cfg.Modules[0].Parameters[0].Value = "clean"
	cfg.Modules[0].HostMappings = []HostMapping{{Pattern: "api.example.com", Target: "127.0.0.1"}}
	if err := validateModules(cfg.Modules); err == nil || !strings.Contains(err.Error(), "host mapping") {
		t.Fatalf("unsafe host mapping error = %v", err)
	}
}

func TestMITMMasterSwitchGatesRuntimeHostsButKeepsCertificateScope(t *testing.T) {
	t.Parallel()
	cfg := Config{
		WLOC: WLOCSettings{Enabled: true},
		Modules: []Module{{
			Enabled: true,
			Hosts:   []string{"api.example.com"},
		}},
	}
	if hosts := activeHostPatterns(cfg); len(hosts) != 0 {
		t.Fatalf("disabled MITM exposed active hosts: %v", hosts)
	}
	if allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 443}) {
		t.Fatal("disabled MITM accepted an inbound SOCKS target")
	}
	if hosts := certificateHostPatterns(cfg); len(hosts) != 3 {
		t.Fatalf("disabled MITM discarded the armed certificate scope: %v", hosts)
	}
	cfg.MITM.Enabled = true
	if !activeInterceptHost(cfg, "api.example.com") || !allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 443}) {
		t.Fatal("enabled MITM did not expose the armed host")
	}
}

func TestRuntimeStopsAfterMITMMasterIsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: "/etc/5gpn/intercept/tls/fullchain.pem", TLSKey: "/etc/5gpn/intercept/tls/privkey.pem",
		UpstreamProxy: ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		MITM:          MITMSettings{Enabled: true, HTTP2: true, QUICFallbackProtection: true},
		WLOC:          WLOCSettings{Accuracy: 25, FailClosed: true, MaxBodyBytes: 8 << 20},
	}
	write := func() {
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go stopWhenMITMDisabled(ctx, store, stop)
	time.Sleep(20 * time.Millisecond)
	cfg.MITM.Enabled = false
	write()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop after the MITM master was disabled")
	}
}

func TestCertificateConfigPathDoesNotCompileModuleJavaScript(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: "/etc/5gpn/intercept/tls/fullchain.pem", TLSKey: "/etc/5gpn/intercept/tls/privkey.pem",
		UpstreamProxy: ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		WLOC:          WLOCSettings{Accuracy: 25, FailClosed: true, MaxBodyBytes: 8 << 20},
		Modules: []Module{{
			ID: "mod-1234567890abcdef", Name: "Fixture", Enabled: true,
			ImportedAt: time.Now().UTC().Format(time.RFC3339), Hosts: []string{"api.example.com"},
			Scripts: []ScriptRule{{ScriptBody: "function ("}},
		}},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertificateConfig(path); err != nil {
		t.Fatalf("minimal certificate validation invoked script validation: %v", err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("full runtime validation accepted invalid JavaScript")
	}
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
