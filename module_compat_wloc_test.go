package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The published wloc bundles, byte for byte, at the revision apple-wloc pins.
//
// Both actions were permanent silent no-ops. Under the Loon persona this runtime
// deliberately presents as, @nsnanocat/util completes with
// `done({response: out})` -- the envelope branch -- and the compat result parser
// recognised no member of it, so the projection came out empty, no error was
// raised, and the exchange went through untouched. For an extension whose whole
// purpose is replacing the device's location, that meant the real location was
// forwarded whatever the operator had configured.
//
// These are staged rather than vendored, following wkRun: the asset is third
// party and the repository does not carry other publishers' dist bundles.
// TestDoneResponseEnvelopeIsNotDropped below pins the same defect without one,
// so the regression is guarded whether or not these run.
//
//	curl -L -o wloc-response.bundle.js https://raw.githubusercontent.com/Yu9191/wloc/eec07a8dc8de6dbaee8eac1fb376e4d03020154a/dist/wloc.js
//	curl -L -o wloc-settings.bundle.js https://raw.githubusercontent.com/Yu9191/wloc/eec07a8dc8de6dbaee8eac1fb376e4d03020154a/dist/wloc-settings.js
func wlocFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Skipf("stage %s to run this", name)
	}
	return string(body)
}

func TestPublishedWlocResponseBundleRewritesTheLocation(t *testing.T) {
	t.Parallel()
	source := wlocFixture(t, "wloc-response.bundle.js")
	if !strings.Contains(source, "{response:") {
		t.Fatal("the pinned asset no longer completes through a response envelope; this test has stopped covering what it was written for")
	}

	module := nativeRuntimeModule()
	module.Enabled = true
	module.PersistentStorage = true
	rule := nativeRuntimeRule(source, "response", "binary")
	rule.Entry = scriptEntryProxyCompat
	rule.TimeoutMS = 30000
	rule.MaxBodyBytes = 8 << 20
	module.Scripts = []ScriptRule{rule}

	request := scriptMessage{
		URL: "https://gs-loc.apple.com/clls/wloc", Method: http.MethodPost, Headers: make(http.Header),
	}
	response := scriptMessage{
		URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte{0x00, 0x01, 0x00, 0x02},
	}

	result, err := newScriptRuntime().execute(
		context.Background(), Config{}, nil, module, rule, request, &response)
	if err != nil {
		t.Fatalf("the published bundle failed: %v", err)
	}
	// The bundle decides for itself whether this payload is one it rewrites; what
	// must never happen again is the completion being understood as "no change"
	// because its envelope was dropped on the floor.
	if !result.ChangedBody && !result.ChangedHeaders && !result.ChangedStatus {
		t.Fatal("the published bundle completed with no change at all, which is what a dropped response envelope looks like")
	}
}

// The request-phase action answers the exchange itself, so its envelope has to
// become a synthetic response rather than a request patch. applyNativePatch
// refuses status on a request patch, so unwrapping it into the wrong phase would
// have turned a silent no-op into a 502 instead of fixing it.
func TestPublishedWlocSettingsBundleAnswersWithASyntheticResponse(t *testing.T) {
	t.Parallel()
	source := wlocFixture(t, "wloc-settings.bundle.js")

	module := nativeRuntimeModule()
	module.Enabled = true
	module.PersistentStorage = true
	rule := nativeRuntimeRule(source, "request", "none")
	rule.Entry = scriptEntryProxyCompat
	rule.TimeoutMS = 10000
	rule.MaxBodyBytes = 1024
	module.Scripts = []ScriptRule{rule}

	request := scriptMessage{
		URL:     "https://gs-loc.apple.com/wloc-settings/save?lon=116.4&lat=39.9",
		Method:  http.MethodGet,
		Headers: make(http.Header),
	}

	result, err := newScriptRuntime().execute(
		context.Background(), Config{}, nil, module, rule, request, nil)
	if err != nil {
		t.Fatalf("the published settings bundle failed: %v", err)
	}
	if !result.Synthetic {
		t.Fatal("a request-phase completion carrying a response must answer the exchange, not vanish")
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("synthetic status = %d, want 200", result.StatusCode)
	}
	var payload map[string]any
	if err := json.Unmarshal(result.Body, &payload); err != nil {
		t.Fatalf("synthetic body is not the JSON the bundle built: %v (%q)", err, string(result.Body))
	}
	if _, exists := payload["success"]; !exists {
		t.Fatalf("synthetic body = %q, want the bundle's own {success: ...} report", string(result.Body))
	}
}

// The envelope, in isolation, in both phases.
func TestDoneResponseEnvelopeIsNotDropped(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}

	t.Run("response phase applies it", func(t *testing.T) {
		t.Parallel()
		rule := nativeRuntimeRule(`$done({response: {status: 201, body: "changed"}})`, "response", "text")
		rule.Entry = scriptEntryProxyCompat
		response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("original")}
		result, err := newScriptRuntime().execute(
			context.Background(), Config{}, nil, module, rule, request, &response)
		if err != nil {
			t.Fatal(err)
		}
		if !result.ChangedBody || string(result.Body) != "changed" || result.StatusCode != 201 {
			t.Fatalf("envelope dropped: %+v", result)
		}
		if result.Synthetic {
			t.Fatal("a response-phase envelope is an edit, not a synthetic reply")
		}
	})

	t.Run("request phase synthesizes", func(t *testing.T) {
		t.Parallel()
		rule := nativeRuntimeRule(`$done({response: {status: 204}})`, "request", "none")
		rule.Entry = scriptEntryProxyCompat
		result, err := newScriptRuntime().execute(
			context.Background(), Config{}, nil, module, rule, request, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Synthetic || result.StatusCode != 204 {
			t.Fatalf("request-phase envelope did not answer the exchange: %+v", result)
		}
	})

	t.Run("the flat shape still works", func(t *testing.T) {
		t.Parallel()
		rule := nativeRuntimeRule(`$done({status: 201, body: "flat"})`, "response", "text")
		rule.Entry = scriptEntryProxyCompat
		response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("original")}
		result, err := newScriptRuntime().execute(
			context.Background(), Config{}, nil, module, rule, request, &response)
		if err != nil {
			t.Fatal(err)
		}
		if string(result.Body) != "flat" || result.StatusCode != 201 {
			t.Fatalf("the documented flat shape regressed: %+v", result)
		}
	})

	t.Run("transport hints alone are still not an error", func(t *testing.T) {
		t.Parallel()
		rule := nativeRuntimeRule(`$done({policy: "DIRECT", url: "https://elsewhere.example"})`, "response", "text")
		rule.Entry = scriptEntryProxyCompat
		response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("original")}
		result, err := newScriptRuntime().execute(
			context.Background(), Config{}, nil, module, rule, request, &response)
		if err != nil {
			t.Fatalf("a completion carrying only transport hints must not fail the action: %v", err)
		}
		if result.ChangedBody || result.ChangedStatus {
			t.Fatalf("transport hints leaked into the message: %+v", result)
		}
	})
}
