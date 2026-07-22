package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func routingString(value string) *string { return &value }
func routingInt(value int) *int          { return &value }
func routingStrings(values ...string) *[]string {
	return &values
}

func validNativeModule(enabled bool) Module {
	manifest := "apiVersion: 5gpn.io/v1\nkind: Extension\n"
	script := `function transform(context) { return { response: { body: context.response.body } } }`
	return Module{
		ID: "io.example.fixture", Version: "1.0.0", Name: "Fixture", Enabled: enabled,
		ImportedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:       ModuleSource{Digest: digestText(manifest), Body: manifest},
		CaptureHosts: []string{"api.example.com"}, CaptureDNS: "trust",
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
		UpstreamProxy:  ProxyConfig{Address: "127.0.0.1:17890", Username: "upstream-user-123", Password: "upstream-password-12345678"},
		MITM:           MITMSettings{Enabled: true, HTTP2: true, QUICFallbackProtection: true},
		Modules:        []Module{validNativeModule(true)},
		ExecutionOrder: []string{"io.example.fixture"},
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
	if loaded.Version != 5 || len(loaded.Modules) != 1 || loaded.Modules[0].ID != "io.example.fixture" || loaded.runtime == nil || len(loaded.runtime.modules) != 1 {
		t.Fatalf("loaded config = %+v", loaded)
	}

	duplicate := strings.Replace(string(body), `"version":5`, `"version":5,"Version":5`, 1)
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestConfigCaptureActionAndCertificateHostBoundsAre512(t *testing.T) {
	t.Parallel()
	makeModule := func(id, prefix string, count int) Module {
		module := validNativeModule(true)
		module.ID = id
		module.CaptureHosts = make([]string, count)
		for index := range module.CaptureHosts {
			module.CaptureHosts[index] = fmt.Sprintf("%s%03d.example.com", prefix, index)
		}
		module.Scripts[0].Match.Hosts = append([]string(nil), module.CaptureHosts...)
		return module
	}
	module := makeModule("io.example.fixture", "h", 512)
	cfg := validNativeConfig()
	cfg.Modules = []Module{module}
	cfg.ExecutionOrder = []string{module.ID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("512 capture/action/certificate hosts rejected: %v", err)
	}
	if err := cfg.ValidateCertificateRequest(); err != nil {
		t.Fatalf("certificate request rejected 512 hosts: %v", err)
	}
	module = makeModule("io.example.fixture", "h", 513)
	cfg.Modules = []Module{module}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "capture_hosts") {
		t.Fatalf("513 capture/action hosts error = %v", err)
	}

	first := makeModule("io.example.first", "a", 256)
	first.Scripts[0].Match.Hosts = []string{first.CaptureHosts[0]}
	second := makeModule("io.example.second", "b", 256)
	second.Scripts[0].Match.Hosts = []string{second.CaptureHosts[0]}
	cfg.Modules = []Module{first, second}
	cfg.ExecutionOrder = []string{first.ID, second.ID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("512 global certificate hosts rejected: %v", err)
	}
	if err := cfg.ValidateCertificateRequest(); err != nil {
		t.Fatalf("certificate request rejected 512 global hosts: %v", err)
	}
	second = makeModule("io.example.second", "b", 257)
	second.Scripts[0].Match.Hosts = []string{second.CaptureHosts[0]}
	cfg.Modules[1] = second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "512") {
		t.Fatalf("513 global certificate hosts error = %v", err)
	}
	if err := cfg.ValidateCertificateRequest(); err == nil || !strings.Contains(err.Error(), "512") {
		t.Fatalf("513 certificate request hosts error = %v", err)
	}
}

func TestConfigRejectsInvalidCaptureDNSBinding(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].CaptureDNS = "automatic"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "capture_dns") {
		t.Fatalf("invalid capture_dns error = %v", err)
	}
}

func TestConfigRoutingRuleJSONPreservesStrictPresence(t *testing.T) {
	t.Parallel()
	valid := configJSONWithRoutingRule(t, `{"action":"reject","domain":"ads.example.com"}`)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}

	invalid := map[string]string{
		"null action":              `{"action":null,"domain":"ads.example.com"}`,
		"null domain":              `{"action":"reject","domain":null,"all_domain_keywords":["ads"]}`,
		"null domain suffix":       `{"action":"reject","domain_suffix":null,"all_domain_keywords":["ads"]}`,
		"null domain keywords":     `{"action":"reject","domain":"ads.example.com","domain_keywords":null}`,
		"null all-domain keywords": `{"action":"reject","domain":"ads.example.com","all_domain_keywords":null}`,
		"null CIDR":                `{"action":"reject","domain":"ads.example.com","ip_cidr":null}`,
		"null network":             `{"action":"reject","domain":"ads.example.com","network":null}`,
		"null destination port":    `{"action":"reject","domain":"ads.example.com","destination_port":null}`,
		"empty action":             `{"action":"","domain":"ads.example.com"}`,
		"empty domain":             `{"action":"reject","domain":"","all_domain_keywords":["ads"]}`,
		"empty domain suffix":      `{"action":"reject","domain_suffix":"","all_domain_keywords":["ads"]}`,
		"empty domain keywords":    `{"action":"reject","domain":"ads.example.com","domain_keywords":[]}`,
		"empty all keywords":       `{"action":"reject","domain":"ads.example.com","all_domain_keywords":[]}`,
		"empty CIDR":               `{"action":"reject","domain":"ads.example.com","ip_cidr":""}`,
		"empty network":            `{"action":"reject","domain":"ads.example.com","network":""}`,
		"zero destination port":    `{"action":"reject","domain":"ads.example.com","destination_port":0}`,
		"unknown field":            `{"action":"reject","domain":"ads.example.com","target":"MATCH"}`,
		"duplicate field":          `{"action":"reject","domain":"ads.example.com","domain":"other.example.com"}`,
		"case duplicate field":     `{"action":"reject","domain":"ads.example.com","Domain":"other.example.com"}`,
	}
	for name, rule := range invalid {
		name, rule := name, rule
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidatePath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(candidatePath, configJSONWithRoutingRule(t, rule), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(candidatePath); err == nil {
				t.Fatal("invalid stored routing rule was accepted")
			}
		})
	}
}

func TestConfigRoutingRulesCollectionPresence(t *testing.T) {
	t.Parallel()
	for name, body := range map[string][]byte{
		"omitted": func() []byte {
			encoded, err := json.Marshal(validNativeConfig())
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}(),
		"empty": configJSONWithRoutingRulesRaw(t, `[]`),
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if name == "empty" && (cfg.Modules[0].RoutingRules == nil || len(cfg.Modules[0].RoutingRules) != 0) {
				t.Fatalf("empty routing_rules = %#v", cfg.Modules[0].RoutingRules)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, configJSONWithRoutingRulesRaw(t, `null`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "routing_rules must not be null") {
		t.Fatalf("null routing_rules error = %v", err)
	}
}

func configJSONWithRoutingRule(t *testing.T, rule string) []byte {
	return configJSONWithRoutingRulesRaw(t, `[`+rule+`]`)
}

func configJSONWithRoutingRulesRaw(t *testing.T, rules string) []byte {
	t.Helper()
	body, err := json.Marshal(validNativeConfig())
	if err != nil {
		t.Fatal(err)
	}
	marker := `"capture_hosts":["api.example.com"],`
	replacement := marker + `"routing_rules":` + rules + `,`
	result := strings.Replace(string(body), marker, replacement, 1)
	if result == string(body) {
		t.Fatal("capture_hosts insertion point was not found")
	}
	return []byte(result)
}

func TestReadConfigBoundedRejectsSymlinkAndNonRegularPaths(t *testing.T) {
	t.Parallel()
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(`{"version":4}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "config.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}
		if _, err := readConfigBounded(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlink error = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := readConfigBounded(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("directory error = %v", err)
		}
	})
}

func TestReadConfigBoundedRejectsPathSwapDuringOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	originalPath := filepath.Join(dir, "original.json")
	if err := os.WriteFile(path, []byte(`{"version":4}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readConfigBoundedWithOpen(path, func(name string) (*os.File, error) {
		if err := os.Rename(name, originalPath); err != nil {
			return nil, err
		}
		if err := os.WriteFile(name, []byte(`{"version":4,"replacement":true}`), 0o600); err != nil {
			return nil, err
		}
		return os.Open(name)
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("path swap error = %v", err)
	}
}

func TestConfigRejectsStaleVersionAndInvalidExecutionOrder(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Version = 3
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must be 5") {
		t.Fatalf("version error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.ExecutionOrder = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "execution_order") {
		t.Fatalf("missing execution order error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.Modules = []Module{}
	cfg.ExecutionOrder = []string{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit empty execution order error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.ExecutionOrder = []string{"io.example.other"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown extension") {
		t.Fatalf("unknown execution order error = %v", err)
	}
	cfg.Modules = append(cfg.Modules, validNativeModule(false))
	cfg.Modules[1].ID = "io.example.second"
	cfg.ExecutionOrder = []string{"io.example.fixture", "io.example.fixture"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate extension") {
		t.Fatalf("duplicate execution order error = %v", err)
	}
}

func TestConfigValidatesNetworkAndEgressPermissions(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].NetworkOrigins = []string{
		"http://events.example.com:8080",
		"https://api.example.com",
	}
	cfg.Modules[0].EgressGroupRequired = true
	cfg.Modules[0].EgressGroup = "Extension Egress"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	invalidOrigins := []string{
		"https://api.example.com:443",
		"https://api.example.com:443/",
		"https://api.example.com:8443/path",
		"https://user@api.example.com:443",
		"https://127.0.0.1:443",
		"https://*.example.com:443",
	}
	for _, origin := range invalidOrigins {
		cfg := validNativeConfig()
		cfg.Modules[0].NetworkOrigins = []string{origin}
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted invalid network origin %q", origin)
		}
	}

	cfg = validNativeConfig()
	cfg.Modules[0].NetworkOrigins = []string{"https://z.example.com", "https://a.example.com"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted origins error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.Modules[0].EgressGroupRequired = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "egress_group") {
		t.Fatalf("missing egress group error = %v", err)
	}
	cfg.Modules[0].Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled extension required egress error = %v", err)
	}
	cfg = validNativeConfig()
	cfg.Modules[0].EgressGroup = "Optional Egress"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("optional egress group error = %v", err)
	}
	cfg.Modules[0].EgressGroup = "Bad,Group"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "comma") {
		t.Fatalf("invalid egress group error = %v", err)
	}
	cfg.Modules[0].EgressGroup = reservedTerminalMatchEgressGroup
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved egress group error = %v", err)
	}
}

func TestConfigValidatesReviewedRoutingRules(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].RoutingRules = []RoutingRule{
		{Action: "reject", Domain: routingString("ads.example.com"), Network: routingString("udp"), DestinationPort: routingInt(443)},
		{Action: "direct", DomainSuffix: routingString("assets.example.com"), AllDomainKeywords: routingStrings("cdn", "static")},
		{Action: "reject", IPCIDR: routingString("203.0.113.7/32")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	for name, rule := range map[string]RoutingRule{
		"invalid action":           {Action: "proxy", Domain: routingString("api.example.com")},
		"multiple primary":         {Action: "reject", Domain: routingString("api.example.com"), DomainSuffix: routingString("example.com")},
		"keyword injection":        {Action: "reject", DomainKeywords: routingStrings("ads),MATCH")},
		"duplicate keyword groups": {Action: "reject", DomainKeywords: routingStrings("ads"), AllDomainKeywords: routingStrings("ads")},
		"single any keyword":       {Action: "reject", DomainKeywords: routingStrings("ads")},
		"noncanonical CIDR":        {Action: "reject", IPCIDR: routingString("203.0.113.7/24")},
		"invalid network":          {Action: "reject", Domain: routingString("api.example.com"), Network: routingString("quic")},
		"invalid port":             {Action: "reject", Domain: routingString("api.example.com"), DestinationPort: routingInt(65536)},
		"explicit zero port":       {Action: "reject", Domain: routingString("api.example.com"), DestinationPort: routingInt(0)},
		"explicit empty domain":    {Action: "reject", Domain: routingString("")},
		"explicit empty network":   {Action: "reject", Domain: routingString("api.example.com"), Network: routingString("")},
		"explicit empty keywords":  {Action: "reject", Domain: routingString("api.example.com"), DomainKeywords: routingStrings()},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validNativeConfig()
			candidate.Modules[0].RoutingRules = []RoutingRule{rule}
			if err := candidate.Validate(); err == nil {
				t.Fatalf("unsafe routing rule was accepted: %+v", rule)
			}
		})
	}
}

func TestConfigRoutingDomainsUseCanonicalCorpus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value string
		valid bool
	}{
		{value: "ads.example.com", valid: true},
		{value: "a-b.example.co.uk", valid: true},
		{value: "Ads.Example.com"},
		{value: " ads.example.com"},
		{value: "ads.example.com "},
		{value: "ads.example.com."},
		{value: "ads.example.123"},
		{value: "ads.example.c"},
		{value: "*.example.com"},
		{value: "ads_example.com"},
		{value: "ads..example.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(strings.ReplaceAll(tc.value, " ", "_"), func(t *testing.T) {
			t.Parallel()
			for _, rule := range []RoutingRule{
				{Action: "reject", Domain: routingString(tc.value)},
				{Action: "direct", DomainSuffix: routingString(tc.value)},
			} {
				err := validateRoutingRules([]RoutingRule{rule})
				if (err == nil) != tc.valid {
					t.Fatalf("value %q valid=%v, error=%v", tc.value, tc.valid, err)
				}
			}
		})
	}
}

func TestConfigBoundsEnabledRoutingRules(t *testing.T) {
	t.Parallel()
	modules := make([]Module, 0, 33)
	for moduleIndex := 0; moduleIndex < 33; moduleIndex++ {
		module := validNativeModule(true)
		module.ID = fmt.Sprintf("io.example.route%02d", moduleIndex)
		module.RoutingRules = make([]RoutingRule, 0, 64)
		for ruleIndex := 0; ruleIndex < 64; ruleIndex++ {
			module.RoutingRules = append(module.RoutingRules, RoutingRule{
				Action: "reject", Domain: routingString(fmt.Sprintf("r%d-%d.example.com", moduleIndex, ruleIndex)),
			})
		}
		modules = append(modules, module)
	}
	if err := validateModules(modules[:32]); err != nil {
		t.Fatalf("exact active routing limit was rejected: %v", err)
	}
	if err := validateModules(modules); err == nil || !strings.Contains(err.Error(), "declared routing rules") {
		t.Fatalf("active routing overflow error = %v", err)
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

func TestCompiledConfigPreservesActiveAndMappedHostSemantics(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].CaptureHosts = []string{"*.example.com", "api.example.net"}
	cfg.Modules[0].Scripts[0].Match.Hosts = []string{"api.example.net"}
	cfg.Modules[0].HostMappings = []HostMapping{{Pattern: "*.example.com", Target: "origin.example.net"}}
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = runtime
	if !activeInterceptHost(cfg, "cdn.example.com") || !activeInterceptHost(cfg, "api.example.net") || activeInterceptHost(cfg, "example.com") {
		t.Fatal("compiled active matcher changed exact/wildcard semantics")
	}
	if got := mappedInterceptTarget(cfg, "cdn.example.com"); got != "origin.example.net" {
		t.Fatalf("compiled mapped target = %q", got)
	}
}
