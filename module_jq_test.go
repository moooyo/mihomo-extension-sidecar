package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func runJQFixture(t *testing.T, program, body string) (string, error) {
	t.Helper()
	code, err := compileJQProgram(program)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runJQ(ctx, code, []byte(body), nil)
	return string(out), err
}

// The expressions below are copied verbatim from the pinned upstream modules.
// That is the whole point of the primitive: the published rule is the
// implementation, not the specification for one.
func TestJQRunsUpstreamExpressionsVerbatim(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		program string
		body    string
		want    string
	}{
		{
			name:    "bilibili tracker conf",
			program: `.data.domains=["wss://tracker.chat.bilibili.com"]`,
			body:    `{"data":{"domains":["wss://evil.example"],"keep":1}}`,
			want:    `{"data":{"domains":["wss://tracker.chat.bilibili.com"],"keep":1}}`,
		},
		{
			name:    "bilibili season payment",
			program: `del(.data.payment)`,
			body:    `{"data":{"payment":{"price":"30"},"title":"x"}}`,
			want:    `{"data":{"title":"x"}}`,
		},
		{
			name:    "zhihu tab list",
			program: `.tab_list |= map(select(.tab_type == "follow" or .tab_type == "recommend" or .tab_type == "hot" or .tab_type == "ring_tab"))`,
			body:    `{"tab_list":[{"tab_type":"follow"},{"tab_type":"ad"},{"tab_type":"hot"}]}`,
			want:    `{"tab_list":[{"tab_type":"follow"},{"tab_type":"hot"}]}`,
		},
		{
			name:    "zhihu recommend components",
			program: `.data |= map(select(.type == "ComponentCard"))`,
			body:    `{"data":[{"type":"ComponentCard"},{"type":"Ad"}]}`,
			want:    `{"data":[{"type":"ComponentCard"}]}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := runJQFixture(t, testCase.program, testCase.body)
			if err != nil {
				t.Fatal(err)
			}
			var wantValue, gotValue any
			if err := json.Unmarshal([]byte(testCase.want), &wantValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
				t.Fatal(err)
			}
			wantText, _ := json.Marshal(wantValue)
			gotText, _ := json.Marshal(gotValue)
			if string(gotText) != string(wantText) {
				t.Fatalf("got %s, want %s", gotText, wantText)
			}
		})
	}
}

func TestJQLeavesANonJSONBodyAlone(t *testing.T) {
	t.Parallel()
	// An origin answers a JSON endpoint with a non-JSON body whenever it likes.
	// api.zhihu.com/search/recommend_query/v1 -- a path a shipped zhihu action
	// filters -- returns the plain text "404 page not found" to an
	// unauthenticated client, and the response-phase caller is fail-closed, so
	// treating that as a failure turned the origin's 404 into a 502 on every
	// such request. Nothing can hide in a body that is not JSON.
	if _, err := runJQFixture(t, ".", "404 page not found"); !errors.Is(err, errJQBodyNotJSON) {
		t.Fatalf("non-JSON body = %v, want errJQBodyNotJSON so the caller can no-op", err)
	}
	if _, err := runJQFixture(t, ".", "<html></html>"); !errors.Is(err, errJQBodyNotJSON) {
		t.Fatalf("HTML body = %v, want errJQBodyNotJSON", err)
	}
}

// The no-op has to reach the caller as "nothing changed", not as an empty body:
// an empty body would truncate the response just as surely as the 502 replaced
// it. Driven through execute() so the dispatch path is covered too.
func TestJQActionOnANonJSONBodyChangesNothing(t *testing.T) {
	t.Parallel()
	rule := ScriptRule{
		ID: "clean", Phase: "response", BodyMode: "text",
		JQProgram: ".data |= map(select(.ad != true))",
		TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
	}
	body := []byte("404 page not found")
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 404, Headers: make(http.Header), Body: body}

	result, err := newScriptRuntime().execute(
		context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response)
	if err != nil {
		t.Fatalf("a jq action on a non-JSON body = %v; the origin's response must survive", err)
	}
	if result.ChangedBody || result.Body != nil || result.Abort {
		t.Fatalf("jq produced %+v on a non-JSON body, want an untouched message", result)
	}
}

func TestJQRejectsAnInvalidProgramAtCompileTime(t *testing.T) {
	t.Parallel()
	// A broken expression must fail when the config is validated, not on the
	// first request that happens to match.
	if _, err := compileJQProgram(".data |= map(select(("); err == nil {
		t.Fatal("expected an unparsable program to be refused")
	}
}

func TestJQRejectsAnOversizedProgram(t *testing.T) {
	t.Parallel()
	if _, err := compileJQProgram("." + strings.Repeat(" ", maxJQProgramBytes)); err == nil {
		t.Fatal("expected an oversized program to be refused")
	}
}

func TestJQStopsAtTheActionDeadline(t *testing.T) {
	t.Parallel()
	// jq can express unbounded recursion. The action's own deadline is what
	// stops it, the same as for a script.
	code, err := compileJQProgram(`[range(100000000)] | length`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := runJQ(ctx, code, []byte(`{}`), nil); err == nil {
		t.Fatal("expected the deadline to stop the program")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("program ran %s past its deadline", elapsed)
	}
}

func TestJQTakesOnlyTheFirstOutput(t *testing.T) {
	t.Parallel()
	// A streaming program would otherwise concatenate documents into one
	// malformed body.
	got, err := runJQFixture(t, `.data[]`, `{"data":[{"a":1},{"b":2}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a":1}` {
		t.Fatalf("got %s, want only the first output", got)
	}
}
