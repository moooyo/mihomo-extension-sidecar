package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const configVersion = 5
const maxConfigBytes = 16 << 20
const maxModuleNetworkOrigins = 256
const maxModuleCaptureHosts = 512
const maxActionMatchHosts = 512
const maxCertificateHosts = 512
const maxModuleRoutingRules = 256
const maxActiveModuleRoutingRules = 2048
const maxModuleRouteKeywords = 8
const reservedTerminalMatchEgressGroup = "__5GPN_TERMINAL_MATCH__"

var nativeExtensionIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{1,126}[a-z0-9])$`)
var nativeExtensionRouteKeywordPattern = regexp.MustCompile(`^[a-z0-9._-]+$`)
var canonicalRoutingDomainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type Config struct {
	Version        int          `json:"version"`
	ExecutionOrder []string     `json:"execution_order"`
	Listen         string       `json:"listen"`
	Username       string       `json:"username"`
	Password       string       `json:"password"`
	TLSCert        string       `json:"tls_cert"`
	TLSKey         string       `json:"tls_key"`
	UpstreamProxy  ProxyConfig  `json:"upstream_proxy"`
	MITM           MITMSettings `json:"mitm"`
	Modules        []Module     `json:"modules,omitempty"`
	runtime        *compiledScriptConfig
}

type ProxyConfig struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type MITMSettings struct {
	Enabled                bool `json:"enabled"`
	HTTP2                  bool `json:"http2"`
	QUICFallbackProtection bool `json:"quic_fallback_protection"`
}

type ModuleSource struct {
	URL    string `json:"url,omitempty"`
	Digest string `json:"digest"`
	Body   string `json:"body"`
}

type ActionMatch struct {
	Hosts       []string `json:"hosts"`
	Schemes     []string `json:"schemes"`
	Methods     []string `json:"methods,omitempty"`
	PathRegex   string   `json:"path_regex"`
	StatusCodes []int    `json:"status_codes,omitempty"`
}

type ScriptRule struct {
	ID           string      `json:"id"`
	Phase        string      `json:"phase"`
	Match        ActionMatch `json:"match"`
	ScriptURL    string      `json:"script_url,omitempty"`
	ScriptDigest string      `json:"script_digest"`
	ScriptBody   string      `json:"script_body"`
	BodyMode     string      `json:"body_mode"`
	TimeoutMS    int         `json:"timeout_ms"`
	MaxBodyBytes int64       `json:"max_body_bytes"`
}

type LocationValue struct {
	Longitude *float64 `json:"longitude,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Accuracy  uint32   `json:"accuracy"`
}

type ModuleSetting struct {
	Key         string          `json:"key"`
	Type        string          `json:"type"`
	Label       string          `json:"label,omitempty"`
	Description string          `json:"description,omitempty"`
	Required    bool            `json:"required"`
	Options     []string        `json:"options,omitempty"`
	Min         *float64        `json:"min,omitempty"`
	Max         *float64        `json:"max,omitempty"`
	Default     json.RawMessage `json:"default,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`
}

type HostMapping struct {
	Pattern string `json:"host"`
	Target  string `json:"target"`
}

type RoutingRule struct {
	Action            string    `json:"action"`
	Domain            *string   `json:"domain,omitempty"`
	DomainSuffix      *string   `json:"domain_suffix,omitempty"`
	DomainKeywords    *[]string `json:"domain_keywords,omitempty"`
	AllDomainKeywords *[]string `json:"all_domain_keywords,omitempty"`
	IPCIDR            *string   `json:"ip_cidr,omitempty"`
	Network           *string   `json:"network,omitempty"`
	DestinationPort   *int      `json:"destination_port,omitempty"`
}

type RoutingRules []RoutingRule

func (rules *RoutingRules) UnmarshalJSON(body []byte) error {
	if routingJSONNull(body) {
		return errors.New("routing_rules must not be null")
	}
	var decoded []RoutingRule
	if err := unmarshalStrictRaw(body, &decoded); err != nil {
		return err
	}
	*rules = decoded
	return nil
}

type rawRoutingRule struct {
	Action            json.RawMessage `json:"action"`
	Domain            json.RawMessage `json:"domain"`
	DomainSuffix      json.RawMessage `json:"domain_suffix"`
	DomainKeywords    json.RawMessage `json:"domain_keywords"`
	AllDomainKeywords json.RawMessage `json:"all_domain_keywords"`
	IPCIDR            json.RawMessage `json:"ip_cidr"`
	Network           json.RawMessage `json:"network"`
	DestinationPort   json.RawMessage `json:"destination_port"`
}

// UnmarshalJSON retains field presence without weakening the config's strict
// JSON boundary. The raw helper is itself decoded with duplicate-key and
// unknown-field rejection because a custom decoder owns this nested object.
func (rule *RoutingRule) UnmarshalJSON(body []byte) error {
	var raw rawRoutingRule
	if err := unmarshalStrictRaw(body, &raw); err != nil {
		return err
	}

	var decoded RoutingRule
	if err := decodeRoutingString(raw.Action, "action", &decoded.Action, true); err != nil {
		return err
	}
	if err := decodeOptionalRoutingString(raw.Domain, "domain", &decoded.Domain); err != nil {
		return err
	}
	if err := decodeOptionalRoutingString(raw.DomainSuffix, "domain_suffix", &decoded.DomainSuffix); err != nil {
		return err
	}
	if err := decodeOptionalRoutingStrings(raw.DomainKeywords, "domain_keywords", &decoded.DomainKeywords); err != nil {
		return err
	}
	if err := decodeOptionalRoutingStrings(raw.AllDomainKeywords, "all_domain_keywords", &decoded.AllDomainKeywords); err != nil {
		return err
	}
	if err := decodeOptionalRoutingString(raw.IPCIDR, "ip_cidr", &decoded.IPCIDR); err != nil {
		return err
	}
	if err := decodeOptionalRoutingString(raw.Network, "network", &decoded.Network); err != nil {
		return err
	}
	if len(raw.DestinationPort) > 0 {
		if routingJSONNull(raw.DestinationPort) {
			return errors.New("destination_port must not be null")
		}
		var value int
		if err := json.Unmarshal(raw.DestinationPort, &value); err != nil {
			return fmt.Errorf("destination_port must be an integer: %w", err)
		}
		if value == 0 {
			return errors.New("destination_port must not be zero when declared")
		}
		decoded.DestinationPort = &value
	}
	*rule = decoded
	return nil
}

func decodeRoutingString(raw json.RawMessage, name string, target *string, required bool) error {
	if len(raw) == 0 {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if routingJSONNull(raw) {
		return fmt.Errorf("%s must not be null", name)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("%s must be a string: %w", name, err)
	}
	if *target == "" {
		return fmt.Errorf("%s must not be empty when declared", name)
	}
	return nil
}

func decodeOptionalRoutingString(raw json.RawMessage, name string, target **string) error {
	var value string
	if err := decodeRoutingString(raw, name, &value, false); err != nil {
		return err
	}
	if len(raw) > 0 {
		*target = &value
	}
	return nil
}

func decodeOptionalRoutingStrings(raw json.RawMessage, name string, target **[]string) error {
	if len(raw) == 0 {
		return nil
	}
	if routingJSONNull(raw) {
		return fmt.Errorf("%s must not be null", name)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("%s must be an array of strings: %w", name, err)
	}
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty when declared", name)
	}
	*target = &values
	return nil
}

func routingJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

type Module struct {
	ID                  string          `json:"id"`
	Version             string          `json:"extension_version"`
	Name                string          `json:"name"`
	Description         string          `json:"description,omitempty"`
	Enabled             bool            `json:"enabled"`
	ImportedAt          string          `json:"imported_at"`
	Source              ModuleSource    `json:"source"`
	CaptureHosts        []string        `json:"capture_hosts"`
	CaptureDNS          string          `json:"capture_dns"`
	HostMappings        []HostMapping   `json:"upstream_mappings,omitempty"`
	RoutingRules        RoutingRules    `json:"routing_rules,omitempty"`
	Settings            []ModuleSetting `json:"settings,omitempty"`
	Scripts             []ScriptRule    `json:"actions,omitempty"`
	PersistentStorage   bool            `json:"persistent_storage"`
	NetworkOrigins      []string        `json:"network_origins"`
	EgressGroupRequired bool            `json:"egress_group_required"`
	EgressGroup         string          `json:"egress_group,omitempty"`
}

func loadConfig(path string) (Config, error) {
	body, err := readConfigBounded(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		return Config{}, fmt.Errorf("compile config runtime: %w", err)
	}
	cfg.runtime = runtime
	return cfg, nil
}

func loadCertificateConfig(path string) (Config, error) {
	body, err := readConfigBounded(path)
	if err != nil {
		return Config{}, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := cfg.ValidateCertificateRequest(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func readConfigBounded(path string) ([]byte, error) {
	return readConfigBoundedWithOpen(path, os.Open)
}

func readConfigBoundedWithOpen(path string, openFile func(string) (*os.File, error)) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("config path is not a regular file")
	}
	// Windows resolves the file ID stored in FileInfo lazily. Comparing the
	// pre-open value with itself pins that identity before the path can change.
	if !os.SameFile(pathInfo, pathInfo) {
		return nil, errors.New("could not establish config file identity")
	}
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, errors.New("opened config is not a regular file")
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("config path changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	return body, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config contains multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			canonicalKey := strings.ToLower(key)
			if _, duplicate := keys[canonicalKey]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[canonicalKey] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing config data: %w", err)
	}
	return nil
}

func (c Config) Validate() error {
	if c.Version != configVersion {
		return fmt.Errorf("config version must be %d", configVersion)
	}
	if err := validateLoopbackAddress("listen", c.Listen); err != nil {
		return err
	}
	if err := validateLoopbackAddress("upstream_proxy.address", c.UpstreamProxy.Address); err != nil {
		return err
	}
	if c.Listen != "127.0.0.1:18080" || c.UpstreamProxy.Address != "127.0.0.1:17890" {
		return errors.New("SOCKS addresses do not match the fixed loopback boundary")
	}
	if len(c.Username) < 16 || len(c.Password) < 24 || len(c.Username) > 255 || len(c.Password) > 255 {
		return errors.New("inbound SOCKS credentials have an invalid length")
	}
	if len(c.UpstreamProxy.Username) < 16 || len(c.UpstreamProxy.Password) < 24 || len(c.UpstreamProxy.Username) > 255 || len(c.UpstreamProxy.Password) > 255 {
		return errors.New("upstream SOCKS credentials have an invalid length")
	}
	if strings.TrimSpace(c.TLSCert) == "" || strings.TrimSpace(c.TLSKey) == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	if err := validateModules(c.Modules); err != nil {
		return err
	}
	if err := validateExecutionOrder(c.Modules, c.ExecutionOrder); err != nil {
		return err
	}
	if len(certificateHostPatterns(c)) > maxCertificateHosts {
		return fmt.Errorf("enabled interception extensions exceed %d unique certificate hosts", maxCertificateHosts)
	}
	return nil
}

func (c Config) ValidateCertificateRequest() error {
	if c.Version != configVersion {
		return fmt.Errorf("config version must be %d", configVersion)
	}
	if c.TLSCert != "/etc/5gpn/intercept/tls/fullchain.pem" || c.TLSKey != "/etc/5gpn/intercept/tls/privkey.pem" {
		return errors.New("TLS paths do not match the fixed interception runtime boundary")
	}
	if len(c.Modules) > 64 {
		return errors.New("at most 64 interception extensions are allowed")
	}
	if err := validateExecutionOrder(c.Modules, c.ExecutionOrder); err != nil {
		return err
	}
	ids := make(map[string]struct{}, len(c.Modules))
	activeRoutingRules := 0
	for _, module := range c.Modules {
		if _, duplicate := ids[module.ID]; duplicate {
			return fmt.Errorf("duplicate extension id %q", module.ID)
		}
		ids[module.ID] = struct{}{}
		if err := validateModuleNetworkPermissions(module); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if err := validateRoutingRules(module.RoutingRules); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if module.CaptureDNS != "trust" && module.CaptureDNS != "china" {
			return fmt.Errorf("extension %q capture_dns must be trust or china", module.ID)
		}
		if !module.Enabled {
			continue
		}
		activeRoutingRules += len(module.RoutingRules)
		if activeRoutingRules > maxActiveModuleRoutingRules {
			return fmt.Errorf("enabled extensions exceed %d declared routing rules", maxActiveModuleRoutingRules)
		}
		if !validModuleID(module.ID) || len(module.CaptureHosts) == 0 || len(module.CaptureHosts) > maxModuleCaptureHosts {
			return fmt.Errorf("enabled extension %q has invalid identity or capture host count", module.ID)
		}
		for _, host := range module.CaptureHosts {
			if !validHostPattern(host) {
				return fmt.Errorf("enabled extension %q has invalid capture host %q", module.ID, host)
			}
		}
	}
	if len(certificateHostPatterns(c)) > maxCertificateHosts {
		return fmt.Errorf("enabled interception extensions exceed %d unique certificate hosts", maxCertificateHosts)
	}
	return nil
}

func validateRoutingRules(rules []RoutingRule) error {
	if len(rules) > maxModuleRoutingRules {
		return fmt.Errorf("routing_rules exceeds %d entries", maxModuleRoutingRules)
	}
	seenRules := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		if rule.Action != "reject" && rule.Action != "direct" {
			return fmt.Errorf("routing rule %d action is invalid", index)
		}
		primary := 0
		if rule.Domain != nil {
			primary++
			if !validCanonicalRoutingDomain(*rule.Domain) {
				return fmt.Errorf("routing rule %d domain is invalid", index)
			}
		}
		if rule.DomainSuffix != nil {
			primary++
			if !validCanonicalRoutingDomain(*rule.DomainSuffix) {
				return fmt.Errorf("routing rule %d domain suffix is invalid", index)
			}
		}
		if rule.IPCIDR != nil {
			primary++
			_, network, err := net.ParseCIDR(*rule.IPCIDR)
			if *rule.IPCIDR == "" || err != nil || network.String() != *rule.IPCIDR {
				return fmt.Errorf("routing rule %d CIDR is invalid", index)
			}
		}
		domainKeywords := []string(nil)
		if rule.DomainKeywords != nil {
			domainKeywords = *rule.DomainKeywords
			if len(domainKeywords) == 0 {
				return fmt.Errorf("routing rule %d domain keywords are empty", index)
			}
		}
		allDomainKeywords := []string(nil)
		if rule.AllDomainKeywords != nil {
			allDomainKeywords = *rule.AllDomainKeywords
			if len(allDomainKeywords) == 0 {
				return fmt.Errorf("routing rule %d all-domain keywords are empty", index)
			}
		}
		if primary > 1 || (primary == 0 && len(domainKeywords) == 0 && len(allDomainKeywords) == 0) ||
			(rule.IPCIDR != nil && (len(domainKeywords) > 0 || len(allDomainKeywords) > 0)) {
			return fmt.Errorf("routing rule %d selector combination is invalid", index)
		}
		if len(domainKeywords) > maxModuleRouteKeywords || !sort.StringsAreSorted(domainKeywords) {
			return fmt.Errorf("routing rule %d domain keywords are invalid", index)
		}
		if len(domainKeywords) == 1 {
			return fmt.Errorf("routing rule %d single domain keyword is not canonical", index)
		}
		seenKeywords := make(map[string]struct{}, len(domainKeywords))
		for _, keyword := range domainKeywords {
			if keyword == "" || len(keyword) > 64 || keyword != strings.ToLower(strings.TrimSpace(keyword)) || !nativeExtensionRouteKeywordPattern.MatchString(keyword) {
				return fmt.Errorf("routing rule %d has an unsafe domain keyword", index)
			}
			if _, duplicate := seenKeywords[keyword]; duplicate {
				return fmt.Errorf("routing rule %d has duplicate domain keywords", index)
			}
			seenKeywords[keyword] = struct{}{}
		}
		if len(allDomainKeywords) > maxModuleRouteKeywords || !sort.StringsAreSorted(allDomainKeywords) {
			return fmt.Errorf("routing rule %d all-domain keywords are invalid", index)
		}
		for _, keyword := range allDomainKeywords {
			if keyword == "" || len(keyword) > 64 || keyword != strings.ToLower(strings.TrimSpace(keyword)) || !nativeExtensionRouteKeywordPattern.MatchString(keyword) {
				return fmt.Errorf("routing rule %d has an unsafe all-domain keyword", index)
			}
			if _, duplicate := seenKeywords[keyword]; duplicate {
				return fmt.Errorf("routing rule %d repeats a domain keyword", index)
			}
			seenKeywords[keyword] = struct{}{}
		}
		if rule.Network != nil {
			if *rule.Network != "tcp" && *rule.Network != "udp" {
				return fmt.Errorf("routing rule %d network is invalid", index)
			}
		}
		if rule.DestinationPort != nil {
			if *rule.DestinationPort < 1 || *rule.DestinationPort > 65535 {
				return fmt.Errorf("routing rule %d destination port is invalid", index)
			}
		}
		body, _ := json.Marshal(rule)
		if _, duplicate := seenRules[string(body)]; duplicate {
			return fmt.Errorf("routing rule %d is duplicated", index)
		}
		seenRules[string(body)] = struct{}{}
	}
	return nil
}

func validCanonicalRoutingDomain(value string) bool {
	return len(value) >= 1 && len(value) <= 253 &&
		value == strings.TrimSpace(value) &&
		value == strings.ToLower(value) &&
		!strings.HasSuffix(value, ".") &&
		canonicalRoutingDomainPattern.MatchString(value)
}

func (c Config) ValidateDeployment() error {
	if c.TLSCert != "/etc/5gpn/intercept/tls/fullchain.pem" || c.TLSKey != "/etc/5gpn/intercept/tls/privkey.pem" {
		return errors.New("TLS paths do not match the fixed interception runtime boundary")
	}
	return nil
}

func validateLoopbackAddress(name, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be a host:port address: %w", name, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s must use an IPv4 loopback address", name)
	}
	if port == "" || port == "0" {
		return fmt.Errorf("%s must use a non-zero port", name)
	}
	return nil
}

func canonicalHost(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	}
	return strings.TrimSuffix(host, ".")
}

func allowedInboundSOCKSTarget(cfg Config, target socksTarget) bool {
	if !cfg.MITM.Enabled || (target.Port != 80 && target.Port != 443) {
		return false
	}
	return activeInterceptHost(cfg, target.Host) || net.ParseIP(target.Host) != nil
}

func activeInterceptHost(cfg Config, value string) bool {
	if !cfg.MITM.Enabled {
		return false
	}
	if cfg.runtime != nil {
		return cfg.runtime.activeHosts.Match(value)
	}
	host := canonicalHost(value)
	for _, pattern := range activeHostPatterns(cfg) {
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func activeHostPatterns(cfg Config) []string {
	if !cfg.MITM.Enabled {
		return nil
	}
	if cfg.runtime != nil {
		return append([]string(nil), cfg.runtime.activePatterns...)
	}
	patterns := make([]string, 0, 16)
	for _, module := range cfg.Modules {
		if module.Enabled {
			patterns = append(patterns, module.CaptureHosts...)
		}
	}
	return uniqueSorted(patterns)
}

func hasActiveExtensions(cfg Config) bool {
	if !cfg.MITM.Enabled {
		return false
	}
	if cfg.runtime != nil {
		return len(cfg.runtime.activePatterns) > 0
	}
	return len(activeHostPatterns(cfg)) > 0
}

func moduleOwnsHost(module Module, host string) bool {
	host = canonicalHost(host)
	for _, pattern := range module.CaptureHosts {
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func mappedInterceptTarget(cfg Config, host string) string {
	host = canonicalHost(host)
	bestPattern := ""
	target := host
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		ownsHost := moduleOwnsHost(module, host)
		if cfg.runtime != nil {
			ownsHost = cfg.runtime.moduleHosts[module.ID].Match(host)
		}
		if !ownsHost {
			continue
		}
		for _, mapping := range module.HostMappings {
			if !matchHostPattern(mapping.Pattern, host) {
				continue
			}
			if mapping.Pattern == host || len(mapping.Pattern) > len(bestPattern) {
				bestPattern = mapping.Pattern
				target = mapping.Target
			}
		}
	}
	return target
}

func certificateHostPatterns(cfg Config) []string {
	patterns := make([]string, 0, 16)
	for _, module := range cfg.Modules {
		if module.Enabled {
			patterns = append(patterns, module.CaptureHosts...)
		}
	}
	return uniqueSorted(patterns)
}

func matchHostPattern(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return len(host) > len(suffix)+1 && strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

func hostPatternCovers(allowed, candidate string) bool {
	if allowed == candidate {
		return true
	}
	if !strings.HasPrefix(allowed, "*.") {
		return false
	}
	base := strings.TrimPrefix(allowed, "*.")
	candidateBase := strings.TrimPrefix(candidate, "*.")
	return strings.HasSuffix(candidateBase, "."+base)
}

func hostCoveredBy(patterns []string, candidate string) bool {
	for _, pattern := range patterns {
		if hostPatternCovers(pattern, candidate) {
			return true
		}
	}
	return false
}

func validateModules(modules []Module) error {
	if len(modules) > 64 {
		return errors.New("at most 64 interception extensions are allowed")
	}
	ids := make(map[string]struct{}, len(modules))
	activeMappings := make(map[string]string)
	activeRoutingRules := 0
	for index, module := range modules {
		if !validModuleID(module.ID) {
			return fmt.Errorf("extension %d has an invalid id", index)
		}
		if _, exists := ids[module.ID]; exists {
			return fmt.Errorf("duplicate extension id %q", module.ID)
		}
		ids[module.ID] = struct{}{}
		if _, err := time.Parse(time.RFC3339, module.ImportedAt); err != nil {
			return fmt.Errorf("extension %q imported_at is invalid", module.ID)
		}
		if strings.TrimSpace(module.Version) == "" || len(module.Version) > 64 || strings.TrimSpace(module.Name) == "" || len(module.Name) > 128 || len(module.Description) > 1024 {
			return fmt.Errorf("extension %q metadata exceeds its bounds", module.ID)
		}
		if len(module.Source.Body) == 0 || len(module.Source.Body) > 2<<20 || module.Source.Digest != digestText(module.Source.Body) {
			return fmt.Errorf("extension %q manifest snapshot digest is invalid", module.ID)
		}
		if len(module.Source.URL) > 4096 || (module.Source.URL != "" && !validSnapshotURL(module.Source.URL)) {
			return fmt.Errorf("extension %q source URL is invalid", module.ID)
		}
		if len(module.CaptureHosts) == 0 || len(module.CaptureHosts) > maxModuleCaptureHosts || !sort.StringsAreSorted(module.CaptureHosts) {
			return fmt.Errorf("extension %q capture_hosts are invalid", module.ID)
		}
		for _, host := range module.CaptureHosts {
			if !validHostPattern(host) {
				return fmt.Errorf("extension %q has an invalid capture host %q", module.ID, host)
			}
		}
		if module.CaptureDNS != "trust" && module.CaptureDNS != "china" {
			return fmt.Errorf("extension %q capture_dns must be trust or china", module.ID)
		}
		if len(module.Scripts)+len(module.HostMappings) == 0 || len(module.Scripts)+len(module.HostMappings) > 256 {
			return fmt.Errorf("extension %q has an invalid action count", module.ID)
		}
		if err := validateModuleSettings(module.Settings, module.Enabled); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if err := validateHostMappings(module.CaptureHosts, module.HostMappings); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if err := validateModuleNetworkPermissions(module); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if err := validateRoutingRules(module.RoutingRules); err != nil {
			return fmt.Errorf("extension %q: %w", module.ID, err)
		}
		if module.Enabled {
			activeRoutingRules += len(module.RoutingRules)
			if activeRoutingRules > maxActiveModuleRoutingRules {
				return fmt.Errorf("enabled extensions exceed %d declared routing rules", maxActiveModuleRoutingRules)
			}
		}
		total := 0
		actionIDs := make(map[string]struct{}, len(module.Scripts))
		for _, rule := range module.Scripts {
			if !validSettingKey(rule.ID) {
				return fmt.Errorf("extension %q has an invalid action id", module.ID)
			}
			if _, duplicate := actionIDs[rule.ID]; duplicate {
				return fmt.Errorf("extension %q has duplicate action %q", module.ID, rule.ID)
			}
			actionIDs[rule.ID] = struct{}{}
			if rule.Phase != "request" && rule.Phase != "response" {
				return fmt.Errorf("extension %q action %q phase is invalid", module.ID, rule.ID)
			}
			if err := validateActionMatch(module.CaptureHosts, rule.Phase, rule.Match); err != nil {
				return fmt.Errorf("extension %q action %q: %w", module.ID, rule.ID, err)
			}
			if len(rule.ScriptURL) > 4096 || (rule.ScriptURL != "" && !validSnapshotURL(rule.ScriptURL)) {
				return fmt.Errorf("extension %q action %q URL is invalid", module.ID, rule.ID)
			}
			if len(rule.ScriptBody) == 0 || len(rule.ScriptBody) > 1<<20 || rule.ScriptDigest != digestText(rule.ScriptBody) {
				return fmt.Errorf("extension %q action %q script snapshot is invalid", module.ID, rule.ID)
			}
			filename := firstNonEmpty(rule.ScriptURL, "extension:"+module.ID+"/"+rule.ID)
			if _, err := goja.Compile(filename, rule.ScriptBody, false); err != nil {
				return fmt.Errorf("extension %q action %q script does not compile: %w", module.ID, rule.ID, err)
			}
			if rule.BodyMode != "none" && rule.BodyMode != "text" && rule.BodyMode != "binary" {
				return fmt.Errorf("extension %q action %q body mode is invalid", module.ID, rule.ID)
			}
			if rule.TimeoutMS < 50 || rule.TimeoutMS > 30000 || rule.MaxBodyBytes < 1024 || rule.MaxBodyBytes > 64<<20 {
				return fmt.Errorf("extension %q action %q limits are invalid", module.ID, rule.ID)
			}
			total += len(rule.ScriptBody)
		}
		if total > 8<<20 {
			return fmt.Errorf("extension %q script snapshots exceed 8388608 bytes", module.ID)
		}
		if module.Enabled {
			if !moduleSettingsReady(module.Settings) {
				return fmt.Errorf("extension %q required settings are not configured", module.ID)
			}
			for _, mapping := range module.HostMappings {
				if target, exists := activeMappings[mapping.Pattern]; exists && target != mapping.Target {
					return fmt.Errorf("enabled extensions conflict on upstream mapping %q", mapping.Pattern)
				}
				activeMappings[mapping.Pattern] = mapping.Target
			}
		}
	}
	return nil
}

func validateExecutionOrder(modules []Module, order []string) error {
	if order == nil {
		return errors.New("execution_order must be an array")
	}
	if len(order) != len(modules) {
		return errors.New("execution_order must contain every extension id exactly once")
	}
	moduleIDs := make(map[string]struct{}, len(modules))
	for _, module := range modules {
		moduleIDs[module.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(order))
	for _, id := range order {
		if _, exists := moduleIDs[id]; !exists {
			return fmt.Errorf("execution_order contains unknown extension id %q", id)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("execution_order contains duplicate extension id %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateModuleNetworkPermissions(module Module) error {
	if len(module.NetworkOrigins) > maxModuleNetworkOrigins {
		return fmt.Errorf("network_origins exceeds %d entries", maxModuleNetworkOrigins)
	}
	previous := ""
	for _, origin := range module.NetworkOrigins {
		canonical, err := canonicalModuleNetworkOrigin(origin)
		if err != nil || canonical != origin {
			return fmt.Errorf("network origin %q is not canonical", origin)
		}
		if previous != "" && origin <= previous {
			return errors.New("network_origins must be sorted and unique")
		}
		previous = origin
	}
	if module.Enabled && module.EgressGroupRequired && strings.TrimSpace(module.EgressGroup) == "" {
		return errors.New("egress_group is required")
	}
	if module.EgressGroup != "" {
		if module.EgressGroup == reservedTerminalMatchEgressGroup {
			return errors.New("egress_group uses a reserved internal name")
		}
		if !utf8.ValidString(module.EgressGroup) || module.EgressGroup != strings.TrimSpace(module.EgressGroup) || len(module.EgressGroup) > 128 {
			return errors.New("egress_group must contain at most 128 bytes without surrounding whitespace")
		}
		for _, character := range module.EgressGroup {
			if character == ',' || unicode.IsControl(character) {
				return errors.New("egress_group contains a comma or control character")
			}
		}
	}
	return nil
}

func canonicalModuleNetworkOrigin(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 || raw != strings.TrimSpace(raw) {
		return "", errors.New("network origin has an invalid length or whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("network origin is not an absolute HTTP origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("network origin cannot contain a path")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("network origin scheme must be http or https")
	}
	host := canonicalHost(parsed.Hostname())
	if host == "" || net.ParseIP(host) != nil || !validHostTarget(host) || strings.Contains(host, ":") {
		return "", errors.New("network origin host is unsafe")
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("network origin port is empty")
	}
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}
	if port == "" {
		port = defaultPort
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("network origin port is invalid")
	}
	port = strconv.Itoa(portNumber)
	if port == defaultPort {
		return scheme + "://" + host, nil
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

func validateActionMatch(captureHosts []string, phase string, match ActionMatch) error {
	if len(match.Hosts) == 0 || len(match.Hosts) > maxActionMatchHosts || len(match.Schemes) == 0 || match.PathRegex == "" {
		return errors.New("match hosts, schemes, and path_regex are required")
	}
	for _, host := range match.Hosts {
		if !validHostPattern(host) || !hostCoveredBy(captureHosts, host) {
			return fmt.Errorf("match host %q is outside capture_hosts", host)
		}
	}
	for _, scheme := range match.Schemes {
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("scheme %q is unsupported", scheme)
		}
	}
	for _, method := range match.Methods {
		if method == "" || method != strings.ToUpper(method) || strings.ContainsAny(method, " \t\r\n") {
			return fmt.Errorf("method %q is invalid", method)
		}
	}
	if _, err := regexp.Compile(match.PathRegex); err != nil {
		return fmt.Errorf("path_regex is invalid: %w", err)
	}
	if phase == "request" && len(match.StatusCodes) > 0 {
		return errors.New("request action cannot match response status codes")
	}
	for _, status := range match.StatusCodes {
		if status < 100 || status > 599 {
			return fmt.Errorf("status code %d is invalid", status)
		}
	}
	return nil
}

func validateModuleSettings(settings []ModuleSetting, requireReady bool) error {
	if len(settings) > 128 {
		return errors.New("extension exceeds 128 settings")
	}
	seen := make(map[string]struct{}, len(settings))
	for _, setting := range settings {
		if !validSettingKey(setting.Key) {
			return fmt.Errorf("setting %q has an invalid key", setting.Key)
		}
		if _, duplicate := seen[setting.Key]; duplicate {
			return fmt.Errorf("setting %q is duplicated", setting.Key)
		}
		seen[setting.Key] = struct{}{}
		if len(setting.Label) > 128 || len(setting.Description) > 512 {
			return fmt.Errorf("setting %q metadata exceeds its bounds", setting.Key)
		}
		if err := validateSettingDefinition(setting); err != nil {
			return fmt.Errorf("setting %q: %w", setting.Key, err)
		}
		if requireReady && setting.Required && !settingReady(setting) {
			return fmt.Errorf("required setting %q is not configured", setting.Key)
		}
	}
	return nil
}

func validateSettingDefinition(setting ModuleSetting) error {
	switch setting.Type {
	case "text":
		if len(setting.Options) > 0 || setting.Min != nil || setting.Max != nil {
			return errors.New("text setting has incompatible constraints")
		}
	case "select":
		if len(setting.Options) == 0 || len(setting.Options) > 64 || setting.Min != nil || setting.Max != nil {
			return errors.New("select setting has invalid options or constraints")
		}
		seen := make(map[string]struct{}, len(setting.Options))
		for _, option := range setting.Options {
			if option == "" || len(option) > 256 {
				return errors.New("select setting contains an invalid option")
			}
			if _, duplicate := seen[option]; duplicate {
				return errors.New("select setting contains duplicate options")
			}
			seen[option] = struct{}{}
		}
	case "boolean", "location":
		if len(setting.Options) > 0 || setting.Min != nil || setting.Max != nil {
			return errors.New("setting has incompatible constraints")
		}
	case "number":
		if len(setting.Options) > 0 || (setting.Min != nil && setting.Max != nil && *setting.Min > *setting.Max) {
			return errors.New("number setting has invalid constraints")
		}
	default:
		return fmt.Errorf("setting type %q is unsupported", setting.Type)
	}
	if len(setting.Default) > 0 {
		if err := validateSettingValue(setting, setting.Default, false); err != nil {
			return fmt.Errorf("default is invalid: %w", err)
		}
	}
	if len(setting.Value) > 0 {
		if err := validateSettingValue(setting, setting.Value, false); err != nil {
			return fmt.Errorf("value is invalid: %w", err)
		}
	}
	return nil
}

func validateSettingValue(setting ModuleSetting, raw json.RawMessage, complete bool) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if complete {
			return errors.New("value is required")
		}
		return nil
	}
	if len(raw) > 64<<10 {
		return errors.New("value exceeds 65536 bytes")
	}
	switch setting.Type {
	case "text", "select":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || len(value) > 4096 {
			return errors.New("value must be a bounded string")
		}
		if complete && strings.TrimSpace(value) == "" {
			return errors.New("value must not be empty")
		}
		if setting.Type == "select" && value != "" && !containsString(setting.Options, value) {
			return errors.New("value is not a declared option")
		}
	case "boolean":
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return errors.New("value must be a boolean")
		}
	case "number":
		var value float64
		if err := json.Unmarshal(raw, &value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("value must be a finite number")
		}
		if (setting.Min != nil && value < *setting.Min) || (setting.Max != nil && value > *setting.Max) {
			return errors.New("value is outside its numeric bounds")
		}
	case "location":
		var value LocationValue
		if err := unmarshalStrictRaw(raw, &value); err != nil {
			return fmt.Errorf("value must be a location object: %w", err)
		}
		if value.Accuracy == 0 || value.Accuracy > 100000 || (value.Longitude == nil) != (value.Latitude == nil) {
			return errors.New("location coordinates or accuracy are invalid")
		}
		if value.Longitude != nil && (*value.Longitude < -180 || *value.Longitude > 180 || math.IsNaN(*value.Longitude) || math.IsInf(*value.Longitude, 0)) {
			return errors.New("longitude is invalid")
		}
		if value.Latitude != nil && (*value.Latitude < -90 || *value.Latitude > 90 || math.IsNaN(*value.Latitude) || math.IsInf(*value.Latitude, 0)) {
			return errors.New("latitude is invalid")
		}
		if complete && value.Longitude == nil {
			return errors.New("coordinates are required")
		}
	}
	return nil
}

func unmarshalStrictRaw(raw []byte, target any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func settingReady(setting ModuleSetting) bool {
	return validateSettingValue(setting, setting.Value, true) == nil
}

func moduleSettingsReady(settings []ModuleSetting) bool {
	for _, setting := range settings {
		if setting.Required && !settingReady(setting) {
			return false
		}
	}
	return true
}

func moduleSettingValues(module Module) (map[string]any, error) {
	values := make(map[string]any, len(module.Settings))
	for _, setting := range module.Settings {
		if len(setting.Value) == 0 {
			continue
		}
		var value any
		if err := json.Unmarshal(setting.Value, &value); err != nil {
			return nil, fmt.Errorf("decode setting %q: %w", setting.Key, err)
		}
		values[setting.Key] = value
	}
	return values, nil
}

func validSettingKey(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validateHostMappings(captureHosts []string, mappings []HostMapping) error {
	seen := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if !validHostPattern(mapping.Pattern) || !hostCoveredBy(captureHosts, mapping.Pattern) || !validHostTarget(mapping.Target) {
			return fmt.Errorf("upstream mapping %q is invalid or outside capture_hosts", mapping.Pattern)
		}
		if _, duplicate := seen[mapping.Pattern]; duplicate {
			return fmt.Errorf("upstream mapping %q is duplicated", mapping.Pattern)
		}
		seen[mapping.Pattern] = struct{}{}
	}
	return nil
}

func validHostTarget(value string) bool {
	value = canonicalHost(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	return !strings.HasPrefix(value, "*.") && value != "localhost" && !strings.HasSuffix(value, ".local") && validHostPattern(value)
}

func validModuleID(id string) bool {
	return len(id) >= 3 && len(id) <= 40 && nativeExtensionIDPattern.MatchString(id)
}

func validSnapshotURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func validHostPattern(pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	if strings.Contains(pattern, "*") || len(pattern) > 253 || !strings.Contains(pattern, ".") {
		return false
	}
	for _, label := range strings.Split(pattern, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func certificateDigest(cfg Config) string {
	return digestText(strings.Join(certificateHostPatterns(cfg), "\n") + "\n")
}

type configStore struct {
	path string

	mu         sync.Mutex
	modTime    time.Time
	badModTime time.Time
	cfg        Config
}

func newConfigStore(path string) (*configStore, error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	return &configStore{path: path, modTime: info.ModTime(), cfg: cfg}, nil
}

func (s *configStore) Current() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.path)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if info.ModTime().Equal(s.modTime) {
		return s.cfg, nil
	}
	cfg, err := loadConfig(s.path)
	if err != nil {
		if !info.ModTime().Equal(s.badModTime) {
			log.Printf("intercept: ignoring invalid replacement config and retaining the last valid snapshot: %v", err)
			s.badModTime = info.ModTime()
		}
		return s.cfg, nil
	}
	s.cfg = cfg
	s.modTime = info.ModTime()
	s.badModTime = time.Time{}
	return cfg, nil
}
