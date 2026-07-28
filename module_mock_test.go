package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func mockRule(mock *MockResponse) ScriptRule {
	return ScriptRule{ID: "mock", Phase: "request", Mock: mock, TimeoutMS: 500, MaxBodyBytes: 1024}
}

func TestMockAnswersARequestWithoutReachingTheOrigin(t *testing.T) {
	t.Parallel()
	// This is what three separate URL-matching scripts were doing: return a
	// fixed body. The action never leaves the gateway.
	result, err := executeMock(mockRule(&MockResponse{
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{}`,
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Synthetic {
		t.Fatal("a request-phase mock must answer synthetically")
	}
	if string(result.Body) != `{}` || result.StatusCode != http.StatusOK {
		t.Fatalf("result = %q/%d, want {} and 200", result.Body, result.StatusCode)
	}
	if result.Headers.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", result.Headers)
	}
}

func TestMockDecodesABinaryFrame(t *testing.T) {
	t.Parallel()
	// The published modules mock gRPC frames, which cannot survive a UTF-8
	// round trip through a manifest, so they are carried as base64 exactly as
	// upstream writes them.
	result, err := executeMock(mockRule(&MockResponse{
		Base64Body: "AAAAAAA=",
		Headers:    map[string]string{"Grpc-Status": "0"},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0, 0, 0, 0}; string(result.Body) != string(want) {
		t.Fatalf("body = %v, want the decoded frame %v", result.Body, want)
	}
}

func TestMockRejectsAmbiguousAndUnsafeDeclarations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mock MockResponse
		want string
	}{
		{"both bodies", MockResponse{Body: "a", Base64Body: "YQ=="}, "both body and base64Body"},
		{"bad base64", MockResponse{Base64Body: "not base64!"}, "not base64"},
		{"bad status", MockResponse{Status: 42}, "not an HTTP status"},
		// A newline in a header value would let a mock inject further headers
		// or a second response into the wire.
		{"header injection", MockResponse{Headers: map[string]string{"X": "a\r\nY: b"}}, "newline"},
		{"header name", MockResponse{Headers: map[string]string{"bad name": "b"}}, "invalid"},
		{"oversized", MockResponse{Body: strings.Repeat("a", maxMockBodyBytes+1)}, "exceeds"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.mock.validate()
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("err = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

func TestJQProgramReadsTheActionSettings(t *testing.T) {
	t.Parallel()
	// Without this a jq action cannot depend on an operator choice, which is
	// what kept the TestFlight storefront rewrite in JavaScript.
	code, err := compileJQProgram(`def ids: {"US":"143441-19,29","JP":"143462-19,29"}; .storefrontId = ids[$settings.storefront]`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runJQ(context.Background(), code, []byte(`{"storefrontId":"000000-00,00","keep":1}`), map[string]any{"storefront": "JP"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"143462-19,29"`) || !strings.Contains(string(got), `"keep":1`) {
		t.Fatalf("got %s, want the selected storefront and the untouched field", got)
	}
}

func TestJQProgramSeesAnEmptySettingsObjectWhenThereAreNone(t *testing.T) {
	t.Parallel()
	// Referencing $settings must not throw for an extension that declares none.
	code, err := compileJQProgram(`.n = ($settings | length)`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runJQ(context.Background(), code, []byte(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"n":0}` {
		t.Fatalf("got %s, want an empty settings object", got)
	}
}
