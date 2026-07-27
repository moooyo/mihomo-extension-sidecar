package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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

	// migrated latches the first time this process makes a bundle live. It is what
	// tells configStore that the coordinator's file is a seam already crossed: a
	// purge withdraws the bundle, it does not restore the document the bundle
	// migrated away from.
	migrated atomic.Bool

	// instanceID is fresh per process. A coordinator that sees it change knows
	// this sidecar restarted and that nothing it attested before still holds.
	instanceID string

	// generation counts activations of this manager, for the readback the
	// coordinator reconciles against. It is not the data plane's comparison key:
	// configStore assigns that, because it is the only thing that sees both this
	// manager and the file it migrated away from.
	generation atomic.Uint64

	// staged names the bundles this process staged and has not committed or
	// aborted yet. It deliberately holds no configuration: the decoded one used to
	// live here so a commit could skip re-reading, which made a bundle that was
	// staged and then abandoned cost tens of kilobytes of resident heap — a
	// decoded Config with its compiled goja programs and regexes — for as long as
	// the process ran, with nothing to bound it. Commit re-reads the record
	// instead, which is what it already did for a bundle staged before a restart.
	staged map[string]struct{}

	logs engineLogPublisher
}

func newBundleManager(store *bundleStore, logs engineLogPublisher) *bundleManager {
	return &bundleManager{
		store:      store,
		instanceID: newInstanceID(),
		staged:     map[string]struct{}{},
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

// Migrated reports whether this process has ever made a bundle live. Unlike
// Active it never goes back to false, so a caller can tell a withdrawal from a
// deployment that has never been pushed a bundle.
func (m *bundleManager) Migrated() bool { return m.migrated.Load() }

// Generation reports how many times this process has made a bundle live, or 0
// when it is serving none.
func (m *bundleManager) Generation() uint64 { return m.generation.Load() }

func (m *bundleManager) setActive(id, digest string, cfg *Config) {
	m.active.Store(cfg)
	m.activeID.Store(&id)
	m.activeDigest.Store(&digest)
	m.migrated.Store(true)
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
	m.generation.Store(1)
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
		// Only a record that is actually staged joins the staged set. A
		// coordinator replaying its transaction re-stages the id it is about to
		// commit, and that id is often the one already serving: recording the live
		// bundle here would list it under stagedBundles and leave it there,
		// because Commit's idempotent repeat returns before the staged set is
		// touched — and abort then refuses it for being active.
		if existing.State == bundleStaged {
			m.staged[id] = struct{}{}
		}
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
	m.staged[id] = struct{}{}
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
	// Read and decoded here, the same way Recover does it, rather than taken from
	// a cache the stage filled. Caching saved one decode out of a commit that
	// spends most of its time in fsync-and-rename cycles, and cost a resident
	// decoded Config per abandoned stage.
	cfg, err := decodeConfig(rec.Document)
	if err != nil {
		return "", fmt.Errorf("bundle %s no longer decodes: %w", id, err)
	}

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

	m.setActive(id, rec.Digest, &cfg)
	generation := m.generation.Add(1)
	delete(m.staged, id)
	m.publish("info", fmt.Sprintf("committed bundle %s as generation %d", id, generation))
	m.pruneSuperseded(current)
	return rec.Digest, nil
}

// bundleRetainedGenerations is how many superseded records a commit leaves
// behind. It must be at least 1: the bundle this commit just replaced is what the
// pointer's Previous names, and rolling back one step is the rollback a
// coordinator actually performs.
//
// Nothing pruned them before, so the store grew by one full document copy per
// commit for the life of the deployment, and store writes are fsynced, so a full
// disk makes the next commit fail — the operation an operator needs when
// something is already wrong. The depth is named rather than assumed because the
// rollback it protects is wider than the store's own comment claims: Commit
// accepts any stored id, not only the one it replaced, so this is how many
// generations a coordinator can walk back without re-uploading.
const bundleRetainedGenerations = 3

// pruneSuperseded drops superseded records past the retained depth.
//
// It runs after the swap and never fails the commit: what it removes is not
// serving anything, and a store that cannot be swept is no reason to reject a
// bundle that already is. The set is recomputed from the store rather than
// remembered, and Delete is idempotent on a missing file and fsyncs the
// directory, so a sweep interrupted halfway is finished by the next commit and a
// store that arrived with a backlog is drained by the first one.
//
// justSuperseded is retained by name rather than by sort. ActivatedAt has
// one-second resolution, so a burst of commits inside one second cannot be
// ordered by it, and that tie must never fall on the record the pointer's
// Previous names.
//
// Staged records are never swept. A stage is a durable promise the coordinator is
// meant to be able to come back to, which is the whole reason staging and commit
// are separate; abort is how it withdraws one.
func (m *bundleManager) pruneSuperseded(justSuperseded string) {
	ids, err := m.store.List()
	if err != nil {
		m.publish("warn", "could not list bundles to prune: "+err.Error())
		return
	}
	older := bundleRetainedGenerations - 1
	activated := make(map[string]int64, len(ids))
	for _, id := range ids {
		if id == justSuperseded {
			continue
		}
		if rec, err := m.store.Get(id); err == nil && rec.State == bundleSuperseded {
			activated[id] = rec.ActivatedAt
		}
	}
	if len(activated) <= older {
		return
	}
	superseded := make([]string, 0, len(activated))
	for id := range activated {
		superseded = append(superseded, id)
	}
	// Within one second the ids only decide which of two things nobody is serving
	// is the one kept, so any total order will do.
	sort.Slice(superseded, func(i, j int) bool {
		if a, b := activated[superseded[i]], activated[superseded[j]]; a != b {
			return a > b
		}
		return superseded[i] > superseded[j]
	})
	for _, id := range superseded[older:] {
		if err := m.store.Delete(id); err != nil {
			m.publish("warn", "could not prune superseded bundle "+id+": "+err.Error())
			return
		}
		m.publish("info", "pruned superseded bundle "+id)
	}
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
	m.generation.Store(0)
	empty := ""
	m.activeID.Store(&empty)
	m.activeDigest.Store(&empty)
	m.staged = map[string]struct{}{}
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
	// The active triple is three separate atomics written in sequence by
	// setActive, so reading them outside m.mu can report one bundle's id with
	// another's digest or generation — and this struct is documented as the
	// authoritative answer a coordinator uses to decide roll-forward or
	// rollback. go test -race cannot see it: every access is atomic, and the
	// race is logical. m.store.List stays outside the lock; it is disk I/O.
	m.mu.Lock()
	staged := make([]string, 0, len(m.staged))
	for id := range m.staged {
		staged = append(staged, id)
	}
	rb := bundleReadback{
		Schema:       bundleStoreSchema,
		InstanceID:   m.instanceID,
		ActiveBundle: m.ActiveID(),
		ActiveDigest: m.ActiveDigest(),
		Staged:       staged,
		Version:      version,
	}
	if cfg := m.active.Load(); cfg != nil {
		rb.Generation = m.Generation()
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
	m.mu.Unlock()

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
