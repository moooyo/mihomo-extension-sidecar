package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Two directives every published module uses, which this manifest could not
// express and so carried as JavaScript instead: a path-scoped reject, and a
// synthetic response.
//
// Neither needs a script. `reject` was ten copies of a 57-byte stub returning
// {abort: true}; `mock` was three separate URL-matching files whose only job
// was to return a fixed body. Both are what the upstream modules declare --
// `reject-dict` and `mock-response-body` in Loon, `[Map Local]` in Surge --
// and expressing them here means the routing surface of an extension is
// reviewable without reading its code.
const (
	maxMockBodyBytes    = 1 << 20
	maxMockHeaderFields = 32
)

// MockResponse is a synthetic reply. Body and Base64Body are exclusive: the
// base64 form exists because the published modules mock binary gRPC frames,
// which cannot survive a UTF-8 round trip through a manifest.
type MockResponse struct {
	Status     int               `json:"status,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Base64Body string            `json:"base64_body,omitempty"`
}

func (m *MockResponse) validate() error {
	if m == nil {
		return nil
	}
	if m.Status != 0 && (m.Status < 100 || m.Status > 599) {
		return fmt.Errorf("mock status %d is not an HTTP status", m.Status)
	}
	if m.Body != "" && m.Base64Body != "" {
		return fmt.Errorf("mock declares both body and base64Body")
	}
	if len(m.Headers) > maxMockHeaderFields {
		return fmt.Errorf("mock declares more than %d headers", maxMockHeaderFields)
	}
	for name, value := range m.Headers {
		if strings.TrimSpace(name) == "" || !httpTokenName(name) {
			return fmt.Errorf("mock header name %q is invalid", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("mock header %q value contains a newline", name)
		}
	}
	body, err := m.bytes()
	if err != nil {
		return err
	}
	if len(body) > maxMockBodyBytes {
		return fmt.Errorf("mock body exceeds %d bytes", maxMockBodyBytes)
	}
	return nil
}

func (m *MockResponse) bytes() ([]byte, error) {
	if m.Base64Body == "" {
		return []byte(m.Body), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(m.Base64Body)
	if err != nil {
		return nil, fmt.Errorf("mock base64Body is not base64: %w", err)
	}
	return decoded, nil
}

func httpTokenName(name string) bool {
	for _, r := range name {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(":()<>@,;\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}

// executeMock builds the synthetic reply. A request-phase action answers the
// client without the request leaving the gateway; a response-phase action
// replaces what the origin returned.
func executeMock(rule ScriptRule, responsePhase bool) (scriptResult, error) {
	body, err := rule.Mock.bytes()
	if err != nil {
		return scriptResult{}, err
	}
	status := rule.Mock.Status
	if status == 0 {
		status = http.StatusOK
	}
	headers := make(http.Header, len(rule.Mock.Headers))
	for name, value := range rule.Mock.Headers {
		headers.Set(name, value)
	}
	return scriptResult{
		Body:           body,
		StatusCode:     status,
		Headers:        headers,
		Synthetic:      !responsePhase,
		ChangedBody:    true,
		ChangedStatus:  true,
		ChangedHeaders: len(headers) > 0,
	}, nil
}
