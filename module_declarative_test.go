package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Every declarative kind driven through execute(), which is what a matched
// action actually calls. The unit tests exercise each executor directly; these
// exist because a kind can be parsed, validated, and unit-tested and still
// never be dispatched -- which is exactly what happened to reject and mock.
func runDeclarative(t *testing.T, rule ScriptRule, request scriptMessage, response *scriptMessage) (scriptResult, error) {
	t.Helper()
	module := Module{ID: "io.example.declarative", CaptureHosts: []string{"api.example.com"}}
	return newScriptRuntime().execute(context.Background(), Config{}, nil, module, rule, request, response)
}

func declarativeRequest() scriptMessage {
	headers := make(http.Header)
	headers.Set("X-Existing", "keep")
	headers.Set("X-Doomed", "gone")
	return scriptMessage{
		URL: "https://api.example.com/v1/thing?a=1", Method: http.MethodPost,
		Headers: headers, Body: []byte(`{"storefrontId":"000000-00,00","other":"keep"}`),
	}
}

func baseRule(phase string) ScriptRule {
	return ScriptRule{ID: "act", Phase: phase, BodyMode: "text", TimeoutMS: 1000, MaxBodyBytes: 1 << 20}
}

func TestExecuteDispatchesReject(t *testing.T) {
	t.Parallel()
	rule := baseRule("request")
	rule.Reject = true
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Abort {
		t.Fatal("a reject action must abort the exchange")
	}
}

func TestExecuteDispatchesMock(t *testing.T) {
	t.Parallel()
	rule := baseRule("request")
	rule.Mock = &MockResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: "{}"}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Synthetic || string(result.Body) != "{}" {
		t.Fatalf("result = %+v, want a synthetic {} reply", result)
	}
}

func TestExecuteDispatchesHeaderEdits(t *testing.T) {
	t.Parallel()
	// The body must survive untouched: that is the whole difference between
	// this and a mock.
	rule := baseRule("request")
	rule.Headers = &HeaderEdits{Set: map[string]string{"X-Added": "1"}, Remove: []string{"X-Doomed"}}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Headers.Get("X-Added") != "1" || result.Headers.Get("X-Doomed") != "" || result.Headers.Get("X-Existing") != "keep" {
		t.Fatalf("headers = %v", result.Headers)
	}
	if result.ChangedBody {
		t.Fatal("a header action must not touch the body")
	}
}

func TestExecuteDispatchesRewriteInPlace(t *testing.T) {
	t.Parallel()
	// Loon's `header` form: the client never learns. Capture groups carry the
	// rest of the URL across.
	rule := baseRule("request")
	rule.Rewrite = &URLRewrite{
		Pattern: `^https://api\.example\.com/(.*)$`,
		To:      "https://mirror.example.net/$1",
	}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedURL || result.URL != "https://mirror.example.net/v1/thing?a=1" {
		t.Fatalf("url = %q changed=%v", result.URL, result.ChangedURL)
	}
	if result.Synthetic {
		t.Fatal("an in-place rewrite must not answer the client")
	}
}

func TestExecuteDispatchesRedirect(t *testing.T) {
	t.Parallel()
	rule := baseRule("request")
	rule.Rewrite = &URLRewrite{
		Pattern: `^https://api\.example\.com/(.*)$`,
		To:      "https://mirror.example.net/$1",
		Status:  http.StatusTemporaryRedirect,
	}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Synthetic || result.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("result = %+v, want a 307", result)
	}
	if result.Headers.Get("Location") != "https://mirror.example.net/v1/thing?a=1" {
		t.Fatalf("location = %q", result.Headers.Get("Location"))
	}
}

func TestExecuteDispatchesBodyReplace(t *testing.T) {
	t.Parallel()
	// Byte-surgical: everything the pattern does not match survives exactly,
	// including key order, which is what the jq substitution could not promise.
	rule := baseRule("request")
	rule.settings = map[string]any{"storefront": "JP"}
	rule.ReplaceBody = &BodyReplace{
		Pattern:  `"storefrontId":"[0-9]{6}-[0-9]{2},[0-9]{2}"`,
		To:       `"storefrontId":"{{settings.storefront}}"`,
		ValueMap: map[string]map[string]string{"storefront": {"US": "143441-19,29", "JP": "143462-19,29"}},
	}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"storefrontId":"143462-19,29","other":"keep"}`
	if string(result.Body) != want {
		t.Fatalf("body = %s, want %s", result.Body, want)
	}
}

func TestBodyReplaceDeclinesAnUnmappedSetting(t *testing.T) {
	t.Parallel()
	// Substituting an empty string into a request body would be worse than
	// leaving it alone.
	rule := baseRule("request")
	rule.settings = map[string]any{"storefront": "ZZ"}
	rule.ReplaceBody = &BodyReplace{
		Pattern:  `"storefrontId":"[^"]*"`,
		To:       `"storefrontId":"{{settings.storefront}}"`,
		ValueMap: map[string]map[string]string{"storefront": {"US": "143441-19,29"}},
	}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ChangedBody {
		t.Fatalf("body = %s, want it untouched", result.Body)
	}
}

func TestRewriteDeclinesWhenItsOwnPatternMisses(t *testing.T) {
	t.Parallel()
	// The action's matcher selected the request; the rewrite's pattern did not.
	// Expanding a template with no captures would build a wrong URL.
	rule := baseRule("request")
	rule.Rewrite = &URLRewrite{Pattern: `^https://other\.example\.com/(.*)$`, To: "https://x/$1"}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ChangedURL || result.Synthetic {
		t.Fatalf("result = %+v, want the request untouched", result)
	}
}

func TestHeaderEditsRefuseInjection(t *testing.T) {
	t.Parallel()
	edits := &HeaderEdits{Set: map[string]string{"X-Bad": "a\r\nY: b"}}
	if err := edits.validate(); err == nil || !strings.Contains(err.Error(), "newline") {
		t.Fatalf("err = %v, want the header refused", err)
	}
}

// A rewrite target may name a setting, which is how upstream's own endpoint
// argument survives the port: Loon interpolates {endpoint} into the rewrite
// line, and this is the same idea with the manifest's own syntax.
func TestRewriteTargetResolvesASettingBeforeItsCaptures(t *testing.T) {
	t.Parallel()
	rule := baseRule("request")
	rule.Rewrite = &URLRewrite{
		Pattern: `^https://api\.example\.com/v1/(.*)$`,
		To:      "https://{{settings.Endpoint}}/v1/$1",
	}
	module := Module{
		ID: "io.example.declarative", CaptureHosts: []string{"api.example.com"}, Network: true,
		Settings: []ModuleSetting{{
			Key: "Endpoint", Type: "select", Required: true, Options: []string{"a.example.net", "b.example.net"},
			Default: []byte(`"a.example.net"`), Value: []byte(`"b.example.net"`),
		}},
	}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, module, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedURL || result.URL != "https://b.example.net/v1/thing?a=1" {
		t.Fatalf("result = %+v, want the operator's endpoint with the rest of the URL carried through", result)
	}
}

// An unresolvable key leaves the request going where it was already going.
// Substituting nothing would build a URL pointing at something else.
func TestRewriteTargetDeclinesAnUnresolvableSetting(t *testing.T) {
	t.Parallel()
	rule := baseRule("request")
	rule.Rewrite = &URLRewrite{
		Pattern: `^https://api\.example\.com/v1/(.*)$`,
		To:      "https://{{settings.Missing}}/v1/$1",
	}
	result, err := runDeclarative(t, rule, declarativeRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ChangedURL || result.Synthetic {
		t.Fatalf("result = %+v, want the request untouched", result)
	}
}

// TestSettingsTemplateTreatsAValueAsDataNotTemplate pins the loop bound.
//
// A substituted value used to be rescanned from the start of the rebuilt
// string, so a value containing its own placeholder was a fixed point and the
// expansion never terminated. Nothing above could stop it: a declarative action
// is dispatched before the VM is created, so there is no goja.Interrupt, and
// neither executeRewrite nor executeBodyReplace takes a context. Two such
// requests held both of the process's body slots and every extension's captured
// traffic failed until a restart.
//
// The subtests are the three reachable shapes. The second needs no manifest
// cooperation at all -- an operator can arm it from a text setting.
func TestSettingsTemplateTreatsAValueAsDataNotTemplate(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		template string
		valueMap map[string]map[string]string
		settings map[string]any
		want     string
	}{
		"self-referencing valueMap entry": {
			template: "{{settings.region}}",
			valueMap: map[string]map[string]string{"region": {"US": "{{settings.region}}"}},
			settings: map[string]any{"region": "US"},
			want:     "{{settings.region}}",
		},
		"operator sets a value that looks like its own placeholder": {
			template: "https://api.example.net/{{settings.token}}",
			settings: map[string]any{"token": "{{settings.token}}"},
			want:     "https://api.example.net/{{settings.token}}",
		},
		"substitution that grows each pass": {
			template: "{{settings.k}}",
			settings: map[string]any{"k": "{{settings.k}}{{settings.k}}"},
			want:     "{{settings.k}}{{settings.k}}",
		},
		"ordinary expansion still resolves every placeholder": {
			template: "https://{{settings.host}}/v1/{{settings.path}}?k={{settings.host}}",
			settings: map[string]any{"host": "origin.example.net", "path": "items"},
			want:     "https://origin.example.net/v1/items?k=origin.example.net",
		},
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan string, 1)
			go func() {
				out, ok := expandSettingsTemplate(tc.template, tc.valueMap, tc.settings)
				if !ok {
					done <- "<declined>"
					return
				}
				done <- out
			}()
			select {
			case got := <-done:
				if got != tc.want {
					t.Fatalf("expanded %q, want %q", got, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("expansion did not terminate")
			}
		})
	}
}
