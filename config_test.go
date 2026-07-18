package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigStrictAndValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "version": 1,
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
	if !cfg.WLOC.Enabled || cfg.WLOC.Longitude == nil || *cfg.WLOC.Longitude != 113.9 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnknownAndNonLoopback(t *testing.T) {
	t.Parallel()
	base := `{
  "version": 1,
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
  "version": 1,
  "listen": "127.0.0.1:18080",
  "username": "inbound-user-123",
  "password": "inbound-password-123456789",
  "tls_cert": "cert.pem",
  "tls_key": "key.pem",
  "upstream_proxy": {"address":"127.0.0.1:17890","username":"upstream-user-123","password":"upstream-password-12345678"},
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
	if cfg.Version != 1 || cfg.Listen != "127.0.0.1:18080" {
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
			ID: "mod-1234567890abcdef", Name: "Fixture", Format: "surge", ImportedAt: time.Now().UTC().Format(time.RFC3339),
			Source: ModuleSource{Digest: digestText(source), Body: source, FetchProfile: "standard"}, Hosts: []string{"api.example.com"},
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

func TestCertificateConfigPathDoesNotCompileModuleJavaScript(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: "/etc/5gpn/intercept/tls/fullchain.pem", TLSKey: "/etc/5gpn/intercept/tls/privkey.pem",
		UpstreamProxy: ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		WLOC:          WLOCSettings{Accuracy: 25, FailClosed: true, MaxBodyBytes: 8 << 20},
		Modules: []Module{{
			ID: "mod-1234567890abcdef", Name: "Fixture", Format: "surge", Enabled: true,
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
