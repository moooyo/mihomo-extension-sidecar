package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func asyncRuntimeCall(t *testing.T, source string, timeoutMS int) (scriptResult, error) {
	t.Helper()
	rule := nativeRuntimeRule(source, "response", "text")
	if timeoutMS > 0 {
		rule.TimeoutMS = timeoutMS
	}
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	return newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), rule, request, &response)
}

func TestAsyncTransformResolvesThroughTheEventLoop(t *testing.T) {
	t.Parallel()
	source := `async function transform(context) {
  const suffix = await Promise.resolve("!")
  return { response: { body: context.response.body + suffix } }
}`
	result, err := asyncRuntimeCall(t, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "ok!" {
		t.Fatalf("body = %q, want %q", got, "ok!")
	}
}

func TestAsyncTransformAwaitsATimer(t *testing.T) {
	t.Parallel()
	// setTimeout is the only scheduling primitive the upstream bundles use, and
	// they use it to race a pending request against a deadline.
	source := `function transform(context) {
  return new Promise((resolve) => {
    setTimeout(() => resolve({ response: { body: "late" } }), 5)
  })
}`
	result, err := asyncRuntimeCall(t, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "late" {
		t.Fatalf("body = %q, want %q", got, "late")
	}
}

func TestAsyncTransformPropagatesRejection(t *testing.T) {
	t.Parallel()
	source := `async function transform(context) {
  throw new Error("boom")
}`
	_, err := asyncRuntimeCall(t, source, 0)
	if err == nil {
		t.Fatal("expected a rejected transform to fail the action")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v, want it to mention the rejection reason", err)
	}
}

func TestAsyncTransformTimesOutOnAPromiseThatNeverSettles(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  return new Promise(() => {})
}`
	started := time.Now()
	_, err := asyncRuntimeCall(t, source, 120)
	if err == nil {
		t.Fatal("expected a never-settling promise to hit the action deadline")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("action took %s, want it bounded by the deadline", elapsed)
	}
}

func TestAsyncTimerLongerThanTheDeadlineLosesToIt(t *testing.T) {
	t.Parallel()
	// A timer past the action deadline is not clamped. Firing it early would
	// run the script's own timeout branch and report a request timeout that
	// never happened, so the action deadline ends the action instead.
	source := `function transform(context) {
  return new Promise((resolve) => {
    setTimeout(() => resolve({ response: { body: "too-late" } }), 60000)
  })
}`
	started := time.Now()
	_, err := asyncRuntimeCall(t, source, 200)
	if err == nil {
		t.Fatal("expected the action deadline to end an action waiting on a longer timer")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("action took %s, want it bounded by the deadline", elapsed)
	}
}

func TestAsyncTimerBudgetIsBounded(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  for (let index = 0; index < 1000; index++) setTimeout(() => {}, 30000)
  return { response: { body: "unreachable" } }
}`
	_, err := asyncRuntimeCall(t, source, 500)
	if err == nil {
		t.Fatal("expected the timer budget to reject unbounded timer allocation")
	}
	if !strings.Contains(err.Error(), "pending timers") {
		t.Fatalf("error = %v, want it to name the timer budget", err)
	}
}

func TestSynchronousTransformStillReturnsDirectly(t *testing.T) {
	t.Parallel()
	// The async path must not change existing synchronous extensions.
	source := `function transform(context) {
  return { response: { body: context.response.body + "-sync" } }
}`
	result, err := asyncRuntimeCall(t, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "ok-sync" {
		t.Fatalf("body = %q, want %q", got, "ok-sync")
	}
}

func TestAsyncLoopDropsCallbacksPostedAfterClose(t *testing.T) {
	t.Parallel()
	loop := newAsyncLoop()
	loop.close()
	delivered := make(chan struct{}, 1)
	loop.post(func() error {
		delivered <- struct{}{}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := loop.wait(ctx, func() bool { return false }); err == nil {
		t.Fatal("expected wait to end on the context, not on a dropped callback")
	}
	select {
	case <-delivered:
		t.Fatal("a callback posted after close must not run")
	default:
	}
}
