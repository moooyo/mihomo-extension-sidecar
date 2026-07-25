package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// bundleManager owns the sidecar's plugin state.
//
// The lifecycle mirrors the runtime overlay's on purpose: stage, then commit
// with a compare-and-swap, then read back. That is not imitation for its own
// sake — the coordinator drives both in one transaction, and a shared shape
// means it does not have to reason about two different failure models to know
// what happened after a crash.
type bundleManager struct {
	mu    sync.Mutex
	store *bundleStore

	// active is the compiled configuration currently serving traffic.
	active atomic.Pointer[Config]
	// activeID and activeDigest identify it.
	activeID     atomic.Pointer[string]
	activeDigest atomic.Pointer[string]

	// instanceID is fresh per process. A coordinator that sees it change knows
	// this sidecar restarted and that nothing it attested before still holds.
	instanceID string

	// staged holds decoded-but-not-live bundles so a commit does not have to
	// re-read and re-decode.
	staged map[string]*Config

	logs engineLogPublisher
}

func newBundleManager(store *bundleStore, logs engineLogPublisher) *bundleManager {
	return &bundleManager{
		store:      store,
		instanceID: newInstanceID(),
		staged:     map[string]*Config{},
		logs:       logs,
	}
}

func newInstanceID() string {
	var b [8]byte
	now := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(now >> (8 * i))
	}
	sum := sha256.Sum256(b[:])
	return hex.EncodeToString(sum[:8])
}

// InstanceID reports the per-process identity.
func (m *bundleManager) InstanceID() string { return m.instanceID }

// Active returns the live configuration, or nil when none is committed.
func (m *bundleManager) Active() *Config { return m.active.Load() }

// ActiveID returns the live bundle id, or "".
func (m *bundleManager) ActiveID() string {
	if p := m.activeID.Load(); p != nil {
		return *p
	}
	return ""
}

// ActiveDigest returns the live bundle digest, or "".
func (m *bundleManager) ActiveDigest() string {
	if p := m.activeDigest.Load(); p != nil {
		return *p
	}
	return ""
}

func (m *bundleManager) setActive(id, digest string, cfg *Config) {
	m.active.Store(cfg)
	m.activeID.Store(&id)
	m.activeDigest.Store(&digest)
}

// Recover loads the bundle this sidecar was serving before it restarted.
//
// It deliberately does not fail the process when the artifact is unusable: the
// sidecar's correct behaviour with no bundle is to serve nothing, and mihomo's
// capture rules fail closed on a processor that is not ready. Refusing to start
// would turn a recoverable state into an outage.
func (m *bundleManager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ptr, err := m.store.Pointer()
	if err != nil {
		return err
	}
	if ptr.Active == "" {
		return nil
	}
	rec, err := m.store.Get(ptr.Active)
	if err != nil {
		return fmt.Errorf("recover bundle %s: %w", ptr.Active, err)
	}
	cfg, err := decodeConfig(rec.Document)
	if err != nil {
		return fmt.Errorf("recover bundle %s: %w", ptr.Active, err)
	}
	cfg.generation = 1
	m.setActive(rec.ID, rec.Digest, &cfg)
	m.publish("info", "recovered bundle "+rec.ID+" after restart")
	return nil
}

// Stage validates and durably persists a bundle without making it live.
//
// Staging is idempotent for an identical document, and refuses a different
// document under an id that already exists — otherwise a retry after a lost
// response could silently replace what the coordinator thinks it staged.
func (m *bundleManager) Stage(id string, document []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validateBundleID(id); err != nil {
		return "", err
	}
	cfg, err := decodeConfig(document)
	if err != nil {
		return "", fmt.Errorf("bundle %s is not a valid configuration: %w", id, err)
	}
	sum := sha256.Sum256(document)
	digest := hex.EncodeToString(sum[:])

	if existing, err := m.store.Get(id); err == nil {
		if existing.Digest != digest {
			return "", fmt.Errorf("%w: bundle %s already exists with a different document", errBundleWrongState, id)
		}
		m.staged[id] = &cfg
		return digest, nil
	} else if !errors.Is(err, errBundleNotFound) {
		return "", err
	}

	rec := &bundleRecord{
		ID: id, State: bundleStaged, Digest: digest,
		Document: document, StagedAt: time.Now().Unix(),
	}
	if err := m.store.Put(rec); err != nil {
		return "", err
	}
	m.staged[id] = &cfg
	m.publish("info", fmt.Sprintf("staged bundle %s (%d extensions)", id, len(cfg.Modules)))
	return digest, nil
}

// Commit makes a staged bundle live, guarded by a compare-and-swap on the
// bundle the coordinator believes is active.
//
// The durable pointer is written before the in-memory swap. A crash between the
// two is recoverable by rolling forward; the reverse order would leave the
// process serving a bundle it would not reload.
func (m *bundleManager) Commit(id, expectedActive string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.ActiveID()
	if current == id {
		// Idempotent repeat: the coordinator lost the response to a commit that
		// landed. Answering with the same success is what lets it roll forward
		// instead of rolling back something that is serving traffic.
		return m.ActiveDigest(), nil
	}
	if current != expectedActive {
		return "", fmt.Errorf("%w: active bundle is %q, the request expected %q",
			errBundleConflict, orNoneBundle(current), orNoneBundle(expectedActive))
	}

	rec, err := m.store.Get(id)
	if err != nil {
		return "", err
	}
	cfg, ok := m.staged[id]
	if !ok {
		decoded, err := decodeConfig(rec.Document)
		if err != nil {
			return "", fmt.Errorf("bundle %s no longer decodes: %w", id, err)
		}
		cfg = &decoded
	}

	generation := uint64(1)
	if prev := m.active.Load(); prev != nil {
		generation = prev.generation + 1
	}
	next := *cfg
	next.generation = generation

	rec.State = bundleActive
	rec.ActivatedAt = time.Now().Unix()
	if err := m.store.Put(rec); err != nil {
		return "", err
	}
	if err := m.store.SetPointer(&bundlePointer{Active: id, Previous: current}); err != nil {
		return "", err
	}
	if current != "" {
		if prev, err := m.store.Get(current); err == nil {
			prev.State = bundleSuperseded
			if err := m.store.Put(prev); err != nil {
				m.publish("warn", "could not mark "+current+" superseded: "+err.Error())
			}
		}
	}

	m.setActive(id, rec.Digest, &next)
	delete(m.staged, id)
	m.publish("info", fmt.Sprintf("committed bundle %s as generation %d", id, generation))
	return rec.Digest, nil
}

// Abort discards a staged bundle. It refuses anything already live: an active
// bundle is superseded by committing another, never erased.
func (m *bundleManager) Abort(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ActiveID() == id {
		return fmt.Errorf("%w: bundle %s is active; supersede it instead of aborting", errBundleWrongState, id)
	}
	rec, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if rec.State == bundleActive {
		return fmt.Errorf("%w: bundle %s is recorded active", errBundleWrongState, id)
	}
	delete(m.staged, id)
	return m.store.Delete(id)
}

// Purge withdraws everything, including the live bundle. The sidecar then
// serves nothing, which mihomo's capture rules treat as not-ready and fail
// closed on.
func (m *bundleManager) Purge() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.active.Store(nil)
	empty := ""
	m.activeID.Store(&empty)
	m.activeDigest.Store(&empty)
	m.staged = map[string]*Config{}
	m.publish("warn", "purged all bundle state")
	return m.store.Purge()
}

// bundleReadback is the authoritative answer to "what is this sidecar serving".
type bundleReadback struct {
	Schema        int      `json:"schema"`
	InstanceID    string   `json:"instanceId"`
	ActiveBundle  string   `json:"activeBundle"`
	ActiveDigest  string   `json:"activeDigest"`
	Generation    uint64   `json:"generation"`
	MasterEnabled bool     `json:"masterEnabled"`
	Extensions    int      `json:"extensions"`
	CaptureHosts  int      `json:"captureHosts"`
	Staged        []string `json:"stagedBundles"`
	Stored        []string `json:"storedBundles"`
	Version       string   `json:"version"`
}

// Readback reports the live state.
func (m *bundleManager) Readback(version string) bundleReadback {
	m.mu.Lock()
	staged := make([]string, 0, len(m.staged))
	for id := range m.staged {
		staged = append(staged, id)
	}
	m.mu.Unlock()

	rb := bundleReadback{
		Schema:       bundleStoreSchema,
		InstanceID:   m.instanceID,
		ActiveBundle: m.ActiveID(),
		ActiveDigest: m.ActiveDigest(),
		Staged:       staged,
		Version:      version,
	}
	if cfg := m.active.Load(); cfg != nil {
		rb.Generation = cfg.generation
		rb.MasterEnabled = cfg.MITM.Enabled
		rb.Extensions = len(cfg.Modules)
		hosts := map[string]struct{}{}
		for _, mod := range cfg.Modules {
			for _, h := range mod.CaptureHosts {
				hosts[h] = struct{}{}
			}
		}
		rb.CaptureHosts = len(hosts)
	}
	if stored, err := m.store.List(); err == nil {
		rb.Stored = stored
	}
	return rb
}

// pluginStatus is the per-extension view the console renders.
type pluginStatus struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Enabled      bool     `json:"enabled"`
	CaptureHosts []string `json:"captureHosts"`
	Actions      int      `json:"actions"`
	Settings     int      `json:"settings"`
	NetworkHosts []string `json:"networkOrigins"`
	EgressGroup  string   `json:"egressGroup,omitempty"`
	Order        int      `json:"order"`
}

// Plugins reports per-extension state, in execution order.
//
// The console previously had to infer this from the coordinator's copy of the
// document. Serving it from the process that actually runs the plugins means
// what the operator sees is what is executing.
func (m *bundleManager) Plugins() []pluginStatus {
	cfg := m.active.Load()
	if cfg == nil {
		return []pluginStatus{}
	}
	order := make(map[string]int, len(cfg.ExecutionOrder))
	for i, id := range cfg.ExecutionOrder {
		order[id] = i
	}
	out := make([]pluginStatus, 0, len(cfg.Modules))
	for _, mod := range cfg.Modules {
		out = append(out, pluginStatus{
			ID:           mod.ID,
			Name:         mod.Name,
			Version:      mod.Version,
			Enabled:      mod.Enabled,
			CaptureHosts: append([]string(nil), mod.CaptureHosts...),
			Actions:      len(mod.Scripts),
			Settings:     len(mod.Settings),
			NetworkHosts: append([]string(nil), mod.NetworkOrigins...),
			EgressGroup:  mod.EgressGroup,
			Order:        order[mod.ID],
		})
	}
	return out
}

func (m *bundleManager) publish(level, message string) {
	if !engineLogPublishingEnabled(m.logs) {
		return
	}
	m.logs.Publish(EngineLog{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Level:   level,
		Source:  "bundle",
		Message: message,
	})
}

func orNoneBundle(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}
