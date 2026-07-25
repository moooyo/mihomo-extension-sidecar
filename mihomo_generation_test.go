package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// stubGenerationCore serves whatever view the test currently wants, standing in
// for mihomo's read-only generation socket.
func stubGenerationCore(t *testing.T, current *atomic.Pointer[generationView], status *atomic.Int32) *generationClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gen.sock")

	mux := http.NewServeMux()
	mux.HandleFunc("/runtime-overlays/5gpn/active", func(w http.ResponseWriter, r *http.Request) {
		if code := status.Load(); code != 0 && code != http.StatusOK {
			w.WriteHeader(int(code))
			return
		}
		v := current.Load()
		if v == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	})

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close() })

	return newGenerationClient(sock)
}

func readyView() *generationView {
	return &generationView{
		BootEpoch:        "epoch-1",
		ActiveGeneration: "g1",
		OverallDigest:    "digest-1",
		ProcessorState:   "ready",
	}
}

func TestBindTransactionCapturesReadyGeneration(t *testing.T) {
	var current atomic.Pointer[generationView]
	var status atomic.Int32
	current.Store(readyView())
	client := stubGenerationCore(t, &current, &status)

	b, err := bindTransaction(context.Background(), client, "5gpn")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if b.Generation != "g1" || b.BootEpoch != "epoch-1" {
		t.Fatalf("binding = %+v", b)
	}
}

// Every non-ready state is a refusal. Continuing under a previously-seen
// generation is exactly how a withdrawn policy keeps being enforced.
func TestBindTransactionFailsClosedWhenNotServiceable(t *testing.T) {
	for _, state := range []string{"quarantined", "not-ready", "degraded", "disabled"} {
		t.Run(state, func(t *testing.T) {
			var current atomic.Pointer[generationView]
			var status atomic.Int32
			v := readyView()
			v.ProcessorState = state
			current.Store(v)
			client := stubGenerationCore(t, &current, &status)

			if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationNotServiceable) {
				t.Fatalf("state %q: err = %v, want not-serviceable", state, err)
			}
		})
	}
}

// "I could not read the view" must be a refusal too. Not knowing the generation
// is not the same as being allowed to proceed under the last one.
func TestBindTransactionFailsClosedWhenViewUnavailable(t *testing.T) {
	var current atomic.Pointer[generationView]
	var status atomic.Int32
	status.Store(http.StatusInternalServerError)
	client := stubGenerationCore(t, &current, &status)

	if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationUnavailable) {
		t.Fatalf("err = %v, want unavailable", err)
	}
}

func TestBindTransactionRefusesUnreachableSocket(t *testing.T) {
	client := newGenerationClient(filepath.Join(t.TempDir(), "does-not-exist.sock"))
	if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationUnavailable) {
		t.Fatalf("err = %v, want unavailable", err)
	}
}

// A boot epoch change means mihomo restarted, which invalidates every lease,
// association and pooled transport minted before it. The processor has to
// notice rather than carry on.
func TestBootEpochChangeIsRefused(t *testing.T) {
	var current atomic.Pointer[generationView]
	var status atomic.Int32
	current.Store(readyView())
	client := stubGenerationCore(t, &current, &status)

	if _, err := bindTransaction(context.Background(), client, "5gpn"); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	restarted := readyView()
	restarted.BootEpoch = "epoch-2"
	current.Store(restarted)
	time.Sleep(generationCacheTTL + 50*time.Millisecond)

	if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationMismatch) {
		t.Fatalf("err = %v, want a mismatch after the core restarted", err)
	}
	// The new epoch is adopted, so the next transaction proceeds under it.
	if _, err := bindTransaction(context.Background(), client, "5gpn"); err != nil {
		t.Fatalf("bind after adopting the new epoch: %v", err)
	}
}

// A binding is per transaction, not per connection: an already-captured
// generation must stop authorizing new work once it is superseded.
func TestBindingStopsBeingValidAfterASwap(t *testing.T) {
	b := transactionBinding{Generation: "g1", BootEpoch: "epoch-1"}

	if !b.stillValid(generationView{BootEpoch: "epoch-1", ActiveGeneration: "g1"}) {
		t.Fatal("a binding for the live generation was rejected")
	}
	if b.stillValid(generationView{BootEpoch: "epoch-1", ActiveGeneration: "g2"}) {
		t.Fatal("a binding for a superseded generation still authorized work")
	}
	if b.stillValid(generationView{BootEpoch: "epoch-2", ActiveGeneration: "g1"}) {
		t.Fatal("a binding survived a core restart")
	}
	if (transactionBinding{}).stillValid(generationView{BootEpoch: "e", ActiveGeneration: "g1"}) {
		t.Fatal("an empty binding authorized work")
	}
}

// The cache is a throughput concession, so it must be bounded: a revoked
// generation may look live for at most one TTL.
func TestGenerationCacheExpires(t *testing.T) {
	var current atomic.Pointer[generationView]
	var status atomic.Int32
	current.Store(readyView())
	client := stubGenerationCore(t, &current, &status)

	if _, err := bindTransaction(context.Background(), client, "5gpn"); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	revoked := readyView()
	revoked.ProcessorState = "not-ready"
	current.Store(revoked)

	// Within the TTL the stale view may still be served.
	if _, err := bindTransaction(context.Background(), client, "5gpn"); err != nil {
		t.Fatalf("within the cache window: %v", err)
	}
	time.Sleep(generationCacheTTL + 50*time.Millisecond)
	if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationNotServiceable) {
		t.Fatalf("after the cache window: err = %v, want not-serviceable", err)
	}
}

// A view with no boot epoch cannot be told apart from a replay of a previous
// process's answer, so it is not a usable view.
func TestViewWithoutBootEpochIsRefused(t *testing.T) {
	var current atomic.Pointer[generationView]
	var status atomic.Int32
	current.Store(&generationView{ActiveGeneration: "g1", ProcessorState: "ready"})
	client := stubGenerationCore(t, &current, &status)

	if _, err := bindTransaction(context.Background(), client, "5gpn"); !errors.Is(err, errGenerationUnavailable) {
		t.Fatalf("err = %v, want unavailable", err)
	}
}
