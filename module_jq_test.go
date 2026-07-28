package main

import (
	"context"
	"encoding/json"
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

func TestJQRejectsANonJSONBody(t *testing.T) {
	t.Parallel()
	// The action matched a path its author declared to be JSON. Forwarding
	// something else unchanged would hide a mismatch between the manifest's
	// pattern and what the endpoint actually returns.
	if _, err := runJQFixture(t, ".", "<html></html>"); err == nil {
		t.Fatal("expected a non-JSON body to be refused")
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
