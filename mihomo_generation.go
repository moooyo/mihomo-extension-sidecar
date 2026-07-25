package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// The processor's view of mihomo's runtime overlay.
//
// The rule this file exists to enforce is narrow and absolute: a transaction
// may only run under a generation mihomo currently publishes as active, and the
// view proving that must come from mihomo itself. An asynchronously mirrored
// file or a locally cached "current generation" pointer would be a second
// commit point, and the whole design exists to have exactly one.

const (
	// generationSocketPath is the read-only socket mihomo exposes to this
	// process. It is a different socket from the coordinator's mutation
	// endpoint on purpose: a read grant must never imply a write grant, and
	// this process is the one assumed to be compromised in the threat model.
	generationSocketPath = "/run/5gpn-intercept/mihomo-generation.sock"

	// generationRequestTimeout bounds a single poll. Failing fast is correct:
	// a transaction whose generation cannot be confirmed must fail closed, and
	// a long wait would turn that into a hang instead of a refusal.
	generationRequestTimeout = 2 * time.Second

	// generationCacheTTL is how long one authoritative view may be reused.
	//
	// It exists so a burst of requests on one connection does not become a
	// burst of socket round trips, and it is deliberately short. Every
	// millisecond of it is a window in which a revoked generation still looks
	// live to this process, so it trades against exactly the property
	// revocation is supposed to provide.
	generationCacheTTL = 250 * time.Millisecond
)

var (
	// errGenerationUnavailable means the authoritative view could not be read.
	// Callers must fail closed: not knowing the generation is not the same as
	// being allowed to proceed under the last one.
	errGenerationUnavailable = errors.New("mihomo generation view unavailable")
	// errGenerationNotServiceable means mihomo has an active generation but is
	// not currently prepared to have its traffic processed — quarantined after
	// a restart, or the readiness lease has lapsed.
	errGenerationNotServiceable = errors.New("mihomo generation is not serviceable")
	// errGenerationMismatch means the view does not describe this process.
	errGenerationMismatch = errors.New("mihomo generation view does not match this processor instance")
)

// generationView is the authoritative projection mihomo publishes.
//
// It carries more than an id on purpose. An id alone could be replayed from a
// previous mihomo process; the boot epoch and fencing identity are what let
// this process notice that the core it is talking to restarted.
type generationView struct {
	BootEpoch        string `json:"bootEpoch"`
	ProcessInstance  string `json:"processInstance"`
	ActiveGeneration string `json:"activeGeneration"`
	OverallDigest    string `json:"overallDigest"`
	ProjectionDigest string `json:"projectionDigest"`
	BundleDigest     string `json:"bundleDigest"`
	CertHostSet      string `json:"certificateHostSetDigest"`
	ProcessorState   string `json:"processorState"`
	CoreRevision     uint64 `json:"coreRevision"`
	ResolverEpoch    uint64 `json:"resolverEpoch"`
	LeaseID          string `json:"leaseId"`
	FencingToken     uint64 `json:"fencingToken"`
	LeaseExpiresAt   int64  `json:"leaseExpiresAt"`
}

// serviceable reports whether capture traffic may actually be processed.
func (v generationView) serviceable() bool { return v.ProcessorState == "ready" }

// generationClient polls mihomo's read-only generation socket.
type generationClient struct {
	hc *http.Client

	mu       sync.Mutex
	cached   generationView
	cachedAt time.Time
	cacheErr error

	// bootEpoch pins the first epoch this process observed. A change means
	// mihomo restarted, which invalidates every lease, fencing token and UDP
	// association minted before it.
	bootEpoch atomic.Pointer[string]
}

func newGenerationClient(socketPath string) *generationClient {
	dialer := &net.Dialer{Timeout: time.Second}
	return &generationClient{
		hc: &http.Client{
			Timeout: generationRequestTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socketPath)
				},
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// view returns the authoritative projection, using the short cache.
func (c *generationClient) view(ctx context.Context, owner string) (generationView, error) {
	c.mu.Lock()
	if time.Since(c.cachedAt) < generationCacheTTL {
		v, err := c.cached, c.cacheErr
		c.mu.Unlock()
		return v, err
	}
	c.mu.Unlock()

	v, err := c.fetch(ctx, owner)

	c.mu.Lock()
	c.cached, c.cacheErr, c.cachedAt = v, err, time.Now()
	c.mu.Unlock()
	return v, err
}

func (c *generationClient) fetch(ctx context.Context, owner string) (generationView, error) {
	var out generationView

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://mihomo/runtime-overlays/"+owner+"/active", nil)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errGenerationUnavailable, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errGenerationUnavailable, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, fmt.Errorf("%w: %v", errGenerationUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%w: HTTP %d", errGenerationUnavailable, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("%w: %v", errGenerationUnavailable, err)
	}
	if out.BootEpoch == "" {
		return out, fmt.Errorf("%w: view carries no boot epoch", errGenerationUnavailable)
	}
	return out, nil
}

// capture resolves the generation a new unit of work must run under, and
// returns it only if that work is actually permitted right now.
//
// Every failure here is a refusal, never a fallback. "I could not confirm the
// generation" and "the generation is not serviceable" both mean the request
// must not be processed: continuing under a previously-seen generation is
// precisely how a revoked policy keeps being enforced after it was withdrawn.
func (c *generationClient) capture(ctx context.Context, owner string) (generationView, error) {
	v, err := c.view(ctx, owner)
	if err != nil {
		return v, err
	}

	// A boot epoch change means the core restarted. Everything minted under the
	// previous epoch — leases, fencing tokens, UDP associations, pooled
	// upstream transports — is invalid, so the caller must not reuse anything
	// it captured before.
	if prev := c.bootEpoch.Load(); prev == nil {
		epoch := v.BootEpoch
		c.bootEpoch.CompareAndSwap(nil, &epoch)
	} else if *prev != v.BootEpoch {
		epoch := v.BootEpoch
		c.bootEpoch.Store(&epoch)
		return v, fmt.Errorf("%w: mihomo restarted (boot epoch %s -> %s)", errGenerationMismatch, *prev, v.BootEpoch)
	}

	if v.ActiveGeneration == "" {
		return v, fmt.Errorf("%w: no active generation", errGenerationNotServiceable)
	}
	if !v.serviceable() {
		return v, fmt.Errorf("%w: processor state is %q", errGenerationNotServiceable, v.ProcessorState)
	}
	return v, nil
}

// BootEpoch reports the pinned epoch, or "" before the first successful poll.
func (c *generationClient) BootEpoch() string {
	if p := c.bootEpoch.Load(); p != nil {
		return *p
	}
	return ""
}

// transactionBinding is the immutable generation one unit of work runs under.
//
// A connection is not a transaction. An HTTP connection outlives many requests,
// an H2 or H3 connection carries many concurrent streams, and a WebSocket can
// outlive several generations. Binding at the connection would pin whatever
// policy happened to be live when the socket opened, which is exactly the
// "permissions pinned to a long-lived TCP connection" the design forbids.
type transactionBinding struct {
	Generation    string
	OverallDigest string
	BundleDigest  string
	BootEpoch     string
	CapturedAt    time.Time
}

// bindTransaction captures the generation for one new transaction.
//
// Call this at every boundary that can expose generation-specific behaviour:
// accepting a processor session, selecting a certificate or ALPN, accepting a
// UDP association, setting up an H3 handshake, and at each new H1 request, H2
// stream or H3 request stream.
func bindTransaction(ctx context.Context, client *generationClient, owner string) (transactionBinding, error) {
	v, err := client.capture(ctx, owner)
	if err != nil {
		return transactionBinding{}, err
	}
	return transactionBinding{
		Generation:    v.ActiveGeneration,
		OverallDigest: v.OverallDigest,
		BundleDigest:  v.BundleDigest,
		BootEpoch:     v.BootEpoch,
		CapturedAt:    time.Now(),
	}, nil
}

// stillValid reports whether an already-started transaction may continue.
//
// An in-flight transaction keeps the bundle it captured — retiring it mid-body
// would corrupt a response nobody asked to change. What must not happen is new
// work starting under a retired generation, which is why this is checked when
// acquiring an upstream connection rather than on every byte.
func (b transactionBinding) stillValid(v generationView) bool {
	if b.Generation == "" {
		return false
	}
	if b.BootEpoch != v.BootEpoch {
		return false
	}
	return b.Generation == v.ActiveGeneration
}
