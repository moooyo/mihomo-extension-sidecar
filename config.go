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
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const configVersion = 1
const maxConfigBytes = 16 << 20

var builtInWLOCHosts = []string{"gs-loc.apple.com", "gs-loc-cn.apple.com"}

type Config struct {
	Version       int          `json:"version"`
	Listen        string       `json:"listen"`
	Username      string       `json:"username"`
	Password      string       `json:"password"`
	TLSCert       string       `json:"tls_cert"`
	TLSKey        string       `json:"tls_key"`
	UpstreamProxy ProxyConfig  `json:"upstream_proxy"`
	WLOC          WLOCSettings `json:"wloc"`
	Modules       []Module     `json:"modules,omitempty"`
}

type ProxyConfig struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type WLOCSettings struct {
	Enabled      bool     `json:"enabled"`
	Longitude    *float64 `json:"longitude"`
	Latitude     *float64 `json:"latitude"`
	Accuracy     uint32   `json:"accuracy"`
	FailClosed   bool     `json:"fail_closed"`
	MaxBodyBytes int64    `json:"max_body_bytes"`
}

type ModuleSource struct {
	URL          string `json:"url,omitempty"`
	Digest       string `json:"digest"`
	Body         string `json:"body"`
	FetchProfile string `json:"fetch_profile"`
	Referer      string `json:"referer,omitempty"`
}

type ScriptRule struct {
	ID           string `json:"id"`
	Phase        string `json:"phase"`
	Pattern      string `json:"pattern"`
	ScriptURL    string `json:"script_url,omitempty"`
	ScriptDigest string `json:"script_digest"`
	ScriptBody   string `json:"script_body"`
	RequiresBody bool   `json:"requires_body"`
	TimeoutMS    int    `json:"timeout_ms"`
	MaxBodyBytes int64  `json:"max_body_bytes"`
	Argument     string `json:"argument,omitempty"`
}

type RewriteRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement,omitempty"`
	Action      string `json:"action"`
}

type HeaderRule struct {
	ID           string `json:"id"`
	Pattern      string `json:"pattern"`
	Operation    string `json:"operation"`
	Header       string `json:"header"`
	Value        string `json:"value,omitempty"`
	ValuePattern string `json:"value_pattern,omitempty"`
	Replacement  string `json:"replacement,omitempty"`
}

type Module struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Description    string        `json:"description,omitempty"`
	Format         string        `json:"format"`
	Enabled        bool          `json:"enabled"`
	Argument       string        `json:"argument,omitempty"`
	ImportedAt     string        `json:"imported_at"`
	Source         ModuleSource  `json:"source"`
	Hosts          []string      `json:"hosts"`
	Scripts        []ScriptRule  `json:"scripts,omitempty"`
	Rewrites       []RewriteRule `json:"rewrites,omitempty"`
	Headers        []HeaderRule  `json:"headers,omitempty"`
	Unsupported    []string      `json:"unsupported,omitempty"`
	PartialAllowed bool          `json:"partial_allowed"`
}

func loadConfig(path string) (Config, error) {
	body, err := readConfigBounded(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
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

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
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
	if len(c.Username) < 16 || len(c.Password) < 24 {
		return errors.New("inbound SOCKS credentials are too short")
	}
	if len(c.Username) > 255 || len(c.Password) > 255 {
		return errors.New("inbound SOCKS credentials are too long")
	}
	if len(c.UpstreamProxy.Username) < 16 || len(c.UpstreamProxy.Password) < 24 {
		return errors.New("upstream SOCKS credentials are too short")
	}
	if len(c.UpstreamProxy.Username) > 255 || len(c.UpstreamProxy.Password) > 255 {
		return errors.New("upstream SOCKS credentials are too long")
	}
	if strings.TrimSpace(c.TLSCert) == "" || strings.TrimSpace(c.TLSKey) == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	if c.WLOC.Accuracy == 0 || c.WLOC.Accuracy > 100000 {
		return errors.New("wloc.accuracy must be between 1 and 100000")
	}
	if c.WLOC.MaxBodyBytes < 1024 || c.WLOC.MaxBodyBytes > 64<<20 {
		return errors.New("wloc.max_body_bytes must be between 1024 and 67108864")
	}
	if c.WLOC.Enabled {
		if c.WLOC.Longitude == nil || c.WLOC.Latitude == nil {
			return errors.New("enabled WLOC interception requires longitude and latitude")
		}
		if *c.WLOC.Longitude < -180 || *c.WLOC.Longitude > 180 {
			return errors.New("wloc.longitude must be between -180 and 180")
		}
		if *c.WLOC.Latitude < -90 || *c.WLOC.Latitude > 90 {
			return errors.New("wloc.latitude must be between -90 and 90")
		}
	}
	if err := validateModules(c.Modules); err != nil {
		return err
	}
	if len(certificateHostPatterns(c)) > 256 {
		return errors.New("enabled interception modules exceed 256 unique certificate hosts")
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
		return errors.New("at most 64 interception modules are allowed")
	}
	ids := make(map[string]struct{}, len(c.Modules))
	for _, module := range c.Modules {
		if _, duplicate := ids[module.ID]; duplicate {
			return fmt.Errorf("duplicate module id %q", module.ID)
		}
		ids[module.ID] = struct{}{}
		if !module.Enabled {
			continue
		}
		if !validModuleID(module.ID) || len(module.Hosts) == 0 || len(module.Hosts) > 256 {
			return fmt.Errorf("enabled module %q has invalid identity or host count", module.ID)
		}
		for _, host := range module.Hosts {
			if !validHostPattern(host) {
				return fmt.Errorf("enabled module %q has invalid host %q", module.ID, host)
			}
		}
	}
	if len(certificateHostPatterns(c)) > 256 {
		return errors.New("enabled interception modules exceed 256 unique certificate hosts")
	}
	return nil
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
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(host, ".")
}

func allowedInboundSOCKSTarget(cfg Config, target socksTarget) bool {
	if target.Port != 443 {
		return false
	}
	return activeInterceptHost(cfg, target.Host) || net.ParseIP(target.Host) != nil
}

func activeInterceptHost(cfg Config, value string) bool {
	host := canonicalHost(value)
	for _, pattern := range activeHostPatterns(cfg) {
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func activeHostPatterns(cfg Config) []string {
	patterns := make([]string, 0, len(builtInWLOCHosts)+16)
	if cfg.WLOC.Enabled {
		patterns = append(patterns, builtInWLOCHosts...)
	}
	for _, module := range cfg.Modules {
		if module.Enabled {
			patterns = append(patterns, module.Hosts...)
		}
	}
	return uniqueSorted(patterns)
}

func certificateHostPatterns(cfg Config) []string {
	patterns := append([]string(nil), builtInWLOCHosts...)
	for _, module := range cfg.Modules {
		if module.Enabled {
			patterns = append(patterns, module.Hosts...)
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

func validateModules(modules []Module) error {
	if len(modules) > 64 {
		return errors.New("at most 64 interception modules are allowed")
	}
	ids := make(map[string]struct{}, len(modules))
	for index, module := range modules {
		if !validModuleID(module.ID) {
			return fmt.Errorf("module %d has an invalid id", index)
		}
		if _, exists := ids[module.ID]; exists {
			return fmt.Errorf("duplicate module id %q", module.ID)
		}
		ids[module.ID] = struct{}{}
		if module.Format != "surge" && module.Format != "loon" {
			return fmt.Errorf("module %q has an invalid format", module.ID)
		}
		if _, err := time.Parse(time.RFC3339, module.ImportedAt); err != nil {
			return fmt.Errorf("module %q imported_at is invalid", module.ID)
		}
		if strings.TrimSpace(module.Name) == "" || len(module.Name) > 128 || len(module.Description) > 1024 || len(module.Argument) > 4096 {
			return fmt.Errorf("module %q metadata exceeds its bounds", module.ID)
		}
		if len(module.Source.Body) == 0 || len(module.Source.Body) > 2<<20 || module.Source.Digest != digestText(module.Source.Body) {
			return fmt.Errorf("module %q source snapshot digest is invalid", module.ID)
		}
		if module.Source.FetchProfile != "standard" && module.Source.FetchProfile != "quantumult-x" {
			return fmt.Errorf("module %q fetch profile is invalid", module.ID)
		}
		if len(module.Source.URL) > 4096 || len(module.Source.Referer) > 4096 {
			return fmt.Errorf("module %q source URL or Referer is too long", module.ID)
		}
		if module.Source.URL != "" && !validSnapshotURL(module.Source.URL) {
			return fmt.Errorf("module %q source URL is invalid", module.ID)
		}
		if module.Source.Referer != "" && !validSnapshotURL(module.Source.Referer) {
			return fmt.Errorf("module %q source Referer is invalid", module.ID)
		}
		if len(module.Hosts) == 0 || len(module.Hosts) > 256 {
			return fmt.Errorf("module %q must declare 1 to 256 hosts", module.ID)
		}
		for _, host := range module.Hosts {
			if !validHostPattern(host) {
				return fmt.Errorf("module %q has an invalid host %q", module.ID, host)
			}
		}
		if len(module.Scripts)+len(module.Rewrites)+len(module.Headers) == 0 || len(module.Scripts)+len(module.Rewrites)+len(module.Headers) > 256 {
			return fmt.Errorf("module %q has an invalid action count", module.ID)
		}
		total := 0
		for _, rule := range module.Scripts {
			if rule.Phase != "request" && rule.Phase != "response" {
				return fmt.Errorf("module %q script phase is invalid", module.ID)
			}
			if len(rule.ScriptURL) > 4096 {
				return fmt.Errorf("module %q script URL is too long", module.ID)
			}
			if !validSnapshotURL(rule.ScriptURL) {
				return fmt.Errorf("module %q script URL is invalid", module.ID)
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("module %q script pattern is invalid: %w", module.ID, err)
			}
			if len(rule.ScriptBody) == 0 || len(rule.ScriptBody) > 1<<20 || rule.ScriptDigest != digestText(rule.ScriptBody) {
				return fmt.Errorf("module %q script snapshot digest is invalid", module.ID)
			}
			if _, err := goja.Compile(rule.ScriptURL, rule.ScriptBody, false); err != nil {
				return fmt.Errorf("module %q script source does not compile: %w", module.ID, err)
			}
			if rule.TimeoutMS < 50 || rule.TimeoutMS > 30000 || rule.MaxBodyBytes < 1024 || rule.MaxBodyBytes > 64<<20 {
				return fmt.Errorf("module %q script limits are invalid", module.ID)
			}
			total += len(rule.ScriptBody)
		}
		if total > 8<<20 {
			return fmt.Errorf("module %q script snapshots exceed 8388608 bytes", module.ID)
		}
		for _, rule := range module.Rewrites {
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("module %q rewrite pattern is invalid: %w", module.ID, err)
			}
			if rule.Action != "reject" && rule.Action != "reject-200" && rule.Action != "reject-dict" && rule.Action != "reject-array" && rule.Action != "redirect-302" && rule.Action != "redirect-307" {
				return fmt.Errorf("module %q rewrite action is invalid", module.ID)
			}
		}
		for _, rule := range module.Headers {
			if _, err := regexp.Compile(rule.Pattern); err != nil || !validHeaderName(rule.Header) {
				return fmt.Errorf("module %q header rewrite is invalid", module.ID)
			}
			switch rule.Operation {
			case "delete":
			case "replace":
				if strings.ContainsAny(rule.Value, "\r\n") {
					return fmt.Errorf("module %q header value is invalid", module.ID)
				}
			case "replace-regex":
				if _, err := regexp.Compile(rule.ValuePattern); err != nil || strings.ContainsAny(rule.Replacement, "\r\n") {
					return fmt.Errorf("module %q header value expression is invalid", module.ID)
				}
			default:
				return fmt.Errorf("module %q header operation is invalid", module.ID)
			}
		}
		if module.Enabled && len(module.Unsupported) > 0 && !module.PartialAllowed {
			return fmt.Errorf("module %q needs partial compatibility acknowledgement", module.ID)
		}
	}
	return nil
}

func validModuleID(id string) bool {
	if len(id) < 20 || len(id) > 36 || !strings.HasPrefix(id, "mod-") {
		return false
	}
	suffix := id[4:]
	if suffix[0] == '-' || suffix[len(suffix)-1] == '-' {
		return false
	}
	for _, r := range suffix {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validSnapshotURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
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
