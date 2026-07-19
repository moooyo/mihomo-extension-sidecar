package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validNativeModule(enabled bool) Module {
	manifest := "apiVersion: 5gpn.io/v1\nkind: Extension\n"
	script := `function transform(context) { return { response: { body: context.response.body } } }`
	return Module{
		ID: "io.example.fixture", Version: "1.0.0", Name: "Fixture", Enabled: enabled,
		ImportedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:       ModuleSource{Digest: digestText(manifest), Body: manifest},
		CaptureHosts: []string{"api.example.com"},
		Scripts: []ScriptRule{{
			ID: "clean", Phase: "response",
			Match:     ActionMatch{Hosts: []string{"api.example.com"}, Schemes: []string{"https"}, PathRegex: "^/"},
			ScriptURL: "https://extensions.example.test/script.js", ScriptDigest: digestText(script), ScriptBody: script,
			BodyMode: "text", TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
		}},
	}
}

func validNativeConfig() Config {
	return Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: "/etc/5gpn/intercept/tls/fullchain.pem", TLSKey: "/etc/5gpn/intercept/tls/privkey.pem",
		UpstreamProxy: ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		MITM:          MITMSettings{Enabled: true, HTTP2: true, QUICFallbackProtection: true},
		Modules:       []Module{validNativeModule(true)},
	}
}

func TestConfigLoadsStrictNativeExtensionDocument(t *testing.T) {
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
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 3 || len(loaded.Modules) != 1 || loaded.Modules[0].ID != "io.example.fixture" {
		t.Fatalf("loaded config = %+v", loaded)
	}

	duplicate := strings.Replace(string(body), `"version":3`, `"version":3,"Version":3`, 1)
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestConfigValidatesNativeScriptAndCaptureBoundary(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Modules[0].Scripts[0].ScriptBody = `function (`
	cfg.Modules[0].Scripts[0].ScriptDigest = digestText(cfg.Modules[0].Scripts[0].ScriptBody)
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid native script was accepted")
	}

	cfg = validNativeConfig()
	cfg.Modules[0].Scripts[0].Match.Hosts = []string{"other.example.com"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "outside capture_hosts") {
		t.Fatalf("capture boundary error = %v", err)
	}
}

func TestConfigRequiresTypedSettingsBeforeEnable(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].Settings = []ModuleSetting{{
		Key: "location", Type: "location", Required: true,
		Default: json.RawMessage(`{"accuracy":25}`), Value: json.RawMessage(`{"accuracy":25}`),
	}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "required setting") {
		t.Fatalf("unconfigured setting error = %v", err)
	}
	cfg.Modules[0].Settings[0].Value = json.RawMessage(`{"longitude":113.9,"latitude":22.5,"accuracy":25}`)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsUnsafeOrOutOfScopeUpstreamMapping(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].HostMappings = []HostMapping{{Pattern: "api.example.com", Target: "127.0.0.1"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "upstream mapping") {
		t.Fatalf("unsafe mapping error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.Modules[0].HostMappings = []HostMapping{{Pattern: "other.example.com", Target: "origin.example.net"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "capture_hosts") {
		t.Fatalf("out-of-scope mapping error = %v", err)
	}
}

func TestConfigAllowsMappingOnlyNativeExtension(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].Scripts = nil
	cfg.Modules[0].HostMappings = []HostMapping{{Pattern: "api.example.com", Target: "origin.example.net"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := mappedInterceptTarget(cfg, "api.example.com"); got != "origin.example.net" {
		t.Fatalf("mapped target = %q", got)
	}
}

func TestMITMMasterAndEnabledExtensionsGateRuntimeHosts(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.MITM.Enabled = false
	if hosts := activeHostPatterns(cfg); len(hosts) != 0 {
		t.Fatalf("disabled MITM exposed active hosts: %v", hosts)
	}
	if hosts := certificateHostPatterns(cfg); len(hosts) != 1 {
		t.Fatalf("certificate request lost enabled extension hosts: %v", hosts)
	}
	cfg.MITM.Enabled = true
	if !activeInterceptHost(cfg, "api.example.com") || !allowedInboundSOCKSTarget(cfg, socksTarget{Host: "api.example.com", Port: 443}) {
		t.Fatal("enabled extension did not expose its capture host")
	}
	cfg.Modules[0].Enabled = false
	if hasActiveExtensions(cfg) || len(certificateHostPatterns(cfg)) != 0 {
		t.Fatal("disabled extension retained an active or certificate host")
	}
}
