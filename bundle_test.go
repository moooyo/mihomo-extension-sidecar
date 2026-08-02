package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testBundleDocument returns a valid version-5 document carrying one real
// extension.
//
// The fixture is derived from actual operator state rather than hand-written,
// because a hand-written one only exercises the fields whoever wrote it
// remembered. This one carries apple-wloc exactly as a live deployment stores
// it, with synthetic credentials.
func testBundleDocument(t *testing.T, extensionID string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	// Re-identify the single extension so callers can stage distinguishable
	// bundles.
	modules := doc["modules"].([]any)
	modules[0].(map[string]any)["id"] = extensionID
	doc["execution_order"] = []string{extensionID}

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Fail fast if the fixture drifts from what the sidecar accepts, rather
	// than letting every test fail with a confusing message.
	if _, err := decodeConfig(out); err != nil {
		t.Fatalf("fixture is not a valid configuration: %v", err)
	}
	return out
}

func newTestBundleManager(t *testing.T) *bundleManager {
	t.Helper()
	store, err := openBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return newBundleManager(store, nil)
}

func TestBundleStageIsIdempotentAndImmutable(t *testing.T) {
	m := newTestBundleManager(t)
	doc := testBundleDocument(t, "io.5gpn.test")

	first, err := m.Stage("b1", doc)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	again, err := m.Stage("b1", doc)
	if err != nil {
		t.Fatalf("restage the identical document: %v", err)
	}
	if first != again {
		t.Fatalf("identical documents produced different digests: %q vs %q", first, again)
	}

	// A different document under the same id must be refused: a retry after a
	// lost response would otherwise silently replace what was staged.
	other := testBundleDocument(t, "io.5gpn.other")
	if _, err := m.Stage("b1", other); !errors.Is(err, errBundleWrongState) {
		t.Fatalf("want errBundleWrongState, got %v", err)
	}
}

// A staged bundle must not be serving anything. Preparing is not arming.
func TestStagedBundleIsNotLive(t *testing.T) {
	m := newTestBundleManager(t)
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if m.Active() != nil {
		t.Fatal("staging made a bundle live")
	}
	if m.ActiveID() != "" {
		t.Fatalf("active id = %q after staging only", m.ActiveID())
	}
}

func TestBundleCommitCASAndIdempotence(t *testing.T) {
	m := newTestBundleManager(t)
	doc := testBundleDocument(t, "io.5gpn.test")
	if _, err := m.Stage("b1", doc); err != nil {
		t.Fatalf("stage: %v", err)
	}

	// The request claims something else is live; nothing is.
	if _, err := m.Commit("b1", "b0"); !errors.Is(err, errBundleConflict) {
		t.Fatalf("want errBundleConflict, got %v", err)
	}

	digest, err := m.Commit("b1", "")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if m.ActiveID() != "b1" {
		t.Fatalf("active = %q, want b1", m.ActiveID())
	}
	// The manager counts its own activations. Config.generation belongs to
	// configStore, which is the only thing that sees both this manager and the
	// file it migrated away from.
	if m.Active() == nil || m.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", m.Generation())
	}

	// A coordinator that lost the response repeats the call. It must get the
	// same success, not a conflict — otherwise it would roll back a bundle that
	// is serving traffic.
	repeat, err := m.Commit("b1", "")
	if err != nil {
		t.Fatalf("repeat commit: %v", err)
	}
	if repeat != digest {
		t.Fatalf("repeat commit returned a different digest")
	}
}

func TestBundleCommitAdvancesGeneration(t *testing.T) {
	m := newTestBundleManager(t)
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.one")); err != nil {
		t.Fatalf("stage b1: %v", err)
	}
	if _, err := m.Commit("b1", ""); err != nil {
		t.Fatalf("commit b1: %v", err)
	}
	if _, err := m.Stage("b2", testBundleDocument(t, "io.5gpn.two")); err != nil {
		t.Fatalf("stage b2: %v", err)
	}
	if _, err := m.Commit("b2", "b1"); err != nil {
		t.Fatalf("commit b2: %v", err)
	}
	if m.Active() == nil || m.Generation() != 2 {
		t.Fatalf("generation did not advance: %d", m.Generation())
	}
	// The superseded bundle is retained so a rollback does not need the
	// coordinator to re-upload it.
	if _, err := m.store.Get("b1"); err != nil {
		t.Fatalf("the superseded bundle was discarded: %v", err)
	}
}

// An active bundle is superseded by committing another, never erased.
func TestAbortRefusesTheLiveBundle(t *testing.T) {
	m := newTestBundleManager(t)
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := m.Abort("b1"); err != nil {
		t.Fatalf("abort staged: %v", err)
	}
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatalf("restage: %v", err)
	}
	if _, err := m.Commit("b1", ""); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := m.Abort("b1"); !errors.Is(err, errBundleWrongState) {
		t.Fatalf("want errBundleWrongState, got %v", err)
	}
}

// The sidecar owns its state, so a restart must reload what it was serving
// rather than wait to be told again.
func TestBundleRecoverAfterRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := openBundleStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first := newBundleManager(store, nil)
	if _, err := first.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := first.Commit("b1", ""); err != nil {
		t.Fatalf("commit: %v", err)
	}

	store2, err := openBundleStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	second := newBundleManager(store2, nil)
	if err := second.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if second.ActiveID() != "b1" {
		t.Fatalf("active after recovery = %q, want b1", second.ActiveID())
	}
	if second.Active() == nil {
		t.Fatal("recovery produced no configuration")
	}
	// A restart is a new process identity, so a coordinator can tell.
	if second.InstanceID() == first.InstanceID() {
		t.Log("note: instance ids collided; they are time-derived and this is possible in a fast test")
	}
}

// A tampered artifact must be reported, not tolerated: a bundle is an
// authorization boundary and a half-written one has no safe interpretation.
func TestBundleStoreDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	store, _ := openBundleStore(dir)
	m := newBundleManager(store, nil)
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatalf("stage: %v", err)
	}

	path := filepath.Join(dir, bundlesDir, "b1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"state": "STAGED"`), []byte(`"state": "ACTIVE"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture did not contain the expected field")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("b1"); !errors.Is(err, errBundleCorrupt) {
		t.Fatalf("want errBundleCorrupt, got %v", err)
	}
}

func TestBundleStoreRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := openBundleStore(dir); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dir, bundleMetaFile)
	raw, _ := os.ReadFile(metaPath)
	bumped := strings.Replace(string(raw), `"schema": 1`, `"schema": 99`, 1)
	if err := os.WriteFile(metaPath, []byte(bumped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openBundleStore(dir); !errors.Is(err, errBundleSchema) {
		t.Fatalf("want errBundleSchema, got %v", err)
	}
}

func TestBundleIDRejectsPathTraversal(t *testing.T) {
	m := newTestBundleManager(t)
	doc := testBundleDocument(t, "io.5gpn.test")
	for _, id := range []string{"../escape", ".hidden", "with/slash", "", strings.Repeat("a", 200)} {
		if _, err := m.Stage(id, doc); err == nil {
			t.Fatalf("bundle id %q was accepted", id)
		}
	}
}

// Purge must leave nothing a later start could resurrect.
func TestBundlePurgeLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	store, _ := openBundleStore(dir)
	m := newBundleManager(store, nil)
	if _, err := m.Stage("b1", testBundleDocument(t, "io.5gpn.test")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Commit("b1", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	store2, _ := openBundleStore(dir)
	m2 := newBundleManager(store2, nil)
	if err := m2.Recover(); err != nil {
		t.Fatalf("recover after purge: %v", err)
	}
	if m2.ActiveID() != "" {
		t.Fatalf("a purged bundle came back as %q", m2.ActiveID())
	}
}

// --- control API ------------------------------------------------------------

// serveControlAPI starts the API on a unix socket and returns a client for it.
func serveControlAPI(t *testing.T, m *bundleManager) *http.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	// No peer policy in tests: the socket lives in a private temp directory and
	// SO_PEERCRED is unavailable on some development platforms.
	srv := newControlServer(m, "test", -1, -1)
	go func() { _ = srv.Serve(sock) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	// Wait for the listener rather than sleeping blindly — but actually wait.
	// Spinning without yielding burns through the iterations in microseconds,
	// long before the goroutine has bound, and then hands back a client whose
	// first request fails with a dial error that looks like a bug in the code
	// under test rather than in this helper.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the control socket %s never appeared", sock)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return client
}

func TestControlAPIRoundTrip(t *testing.T) {
	m := newTestBundleManager(t)
	client := serveControlAPI(t, m)
	doc := testBundleDocument(t, "io.5gpn.apple-wloc")

	resp, err := client.Get("http://sidecar/capabilities")
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	var caps capabilitiesResponse
	decodeBody(t, resp, &caps)
	if caps.Schema != controlAPISchema {
		t.Fatalf("schema = %d, want %d", caps.Schema, controlAPISchema)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("responses carry the live bundle identity and must not be cacheable")
	}

	req, _ := http.NewRequest(http.MethodPut, "http://sidecar/bundles/b1", bytes.NewReader(doc))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	var staged stageResponse
	decodeBody(t, resp, &staged)
	if staged.Digest == "" {
		t.Fatal("stage returned no digest")
	}

	// Still not live.
	resp, _ = client.Get("http://sidecar/state")
	var state bundleReadback
	decodeBody(t, resp, &state)
	if state.ActiveBundle != "" {
		t.Fatalf("staging made %q live", state.ActiveBundle)
	}

	req, _ = http.NewRequest(http.MethodPost, "http://sidecar/bundles/b1/commit",
		strings.NewReader(`{"expectedActiveBundle":""}`))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	var committed commitResponse
	decodeBody(t, resp, &committed)
	if committed.Generation != 1 {
		t.Fatalf("generation = %d, want 1", committed.Generation)
	}

	resp, _ = client.Get("http://sidecar/plugins")
	var plugins struct {
		ActiveBundle string         `json:"activeBundle"`
		Plugins      []pluginStatus `json:"plugins"`
	}
	decodeBody(t, resp, &plugins)
	if len(plugins.Plugins) != 1 || plugins.Plugins[0].ID != "io.5gpn.apple-wloc" {
		t.Fatalf("plugins = %+v", plugins.Plugins)
	}
	// The real apple-wloc manifest declares both Apple location endpoints, and
	// the console needs to see exactly what the running process holds.
	p := plugins.Plugins[0]
	if len(p.CaptureHosts) != 2 || p.Name == "" || p.Version == "" {
		t.Fatalf("the plugin view is incomplete: %+v", p)
	}
	if p.Actions == 0 || p.Settings == 0 {
		t.Fatalf("actions and settings were not reported: %+v", p)
	}
}

// The coordinator branches on the code, so a conflict must be reported as one
// rather than as a generic failure.
func TestControlAPIReportsConflictWithAStableCode(t *testing.T) {
	m := newTestBundleManager(t)
	client := serveControlAPI(t, m)
	doc := testBundleDocument(t, "io.5gpn.test")

	req, _ := http.NewRequest(http.MethodPut, "http://sidecar/bundles/b1", bytes.NewReader(doc))
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPost, "http://sidecar/bundles/b1/commit",
		strings.NewReader(`{"expectedActiveBundle":"b0"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	var body controlError
	decodeBody(t, resp, &body)
	if body.Code != "cas_conflict" {
		t.Fatalf("code = %q, want cas_conflict", body.Code)
	}
}

func TestControlAPIRejectsAnInvalidDocument(t *testing.T) {
	m := newTestBundleManager(t)
	client := serveControlAPI(t, m)

	req, _ := http.NewRequest(http.MethodPut, "http://sidecar/bundles/b1",
		strings.NewReader(`{"version": 6, "modules": "not an array"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("an invalid document was accepted with status %d", resp.StatusCode)
	}
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", resp.Request.URL.Path, err)
	}
}

// bundleReadback is documented as the authoritative answer to what this sidecar
// is serving, and a coordinator decides roll-forward or rollback from it. The
// active identity is three separate atomics that setActive writes in sequence,
// so reading them outside m.mu reported one bundle's id with another's digest or
// generation. go test -race cannot see this: every access is atomic and the race
// is logical.
func TestReadbackNeverStraddlesAnActivation(t *testing.T) {
	store, err := openBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newBundleManager(store, nil)

	type activation struct {
		id     string
		digest string
	}
	activations := []activation{
		{id: "bundle-aaaa", digest: "digest-aaaa"},
		{id: "bundle-bbbb", digest: "digest-bbbb"},
	}
	expected := map[string]activation{}
	for _, a := range activations {
		expected[a.id] = a
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			a := activations[index%len(activations)]
			manager.mu.Lock()
			manager.setActive(a.id, a.digest, &Config{})
			manager.mu.Unlock()
		}
	}()

	reads, torn := 0, 0
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		rb := manager.Readback("test")
		if rb.ActiveBundle == "" {
			continue
		}
		reads++
		want, ok := expected[rb.ActiveBundle]
		if !ok {
			t.Fatalf("readback reported an id nothing ever activated: %q", rb.ActiveBundle)
		}
		if rb.ActiveDigest != want.digest {
			torn++
		}
	}
	close(stop)
	<-done

	if reads < 1000 {
		t.Fatalf("only %d readbacks observed; the test did not exercise the race", reads)
	}
	if torn != 0 {
		t.Fatalf("%d of %d readbacks straddled an activation", torn, reads)
	}
	t.Logf("%d readbacks, %d torn", reads, torn)
}

// A coordinator replaying its transaction re-stages the id it is about to
// commit, and that id is often the one already serving. Recording the live
// bundle in the staged set listed it under stagedBundles forever: Commit's
// idempotent repeat returns before the staged set is touched, and Abort then
// refuses the id for being active.
func TestReStagingTheLiveBundleDoesNotListItAsStaged(t *testing.T) {
	store, err := openBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newBundleManager(store, nil)
	document, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Stage("bundle-live", document); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Commit("bundle-live", ""); err != nil {
		t.Fatal(err)
	}
	if got := manager.Readback("test").Staged; len(got) != 0 {
		t.Fatalf("a committed bundle stayed in the staged set: %v", got)
	}

	// The replay: same id, same document, after the commit landed.
	if _, err := manager.Stage("bundle-live", document); err != nil {
		t.Fatalf("re-staging the live bundle failed: %v", err)
	}
	rb := manager.Readback("test")
	if len(rb.Staged) != 0 {
		t.Fatalf("re-staging the live bundle listed it as staged: %v", rb.Staged)
	}
	if rb.ActiveBundle != "bundle-live" {
		t.Fatalf("re-staging disturbed the live bundle: %q", rb.ActiveBundle)
	}
	// And the coordinator can still finish its replay.
	if _, err := manager.Commit("bundle-live", "bundle-live"); err != nil {
		t.Fatalf("replayed commit failed: %v", err)
	}
}

// Nothing ever pruned superseded records: bundleStore.Delete had exactly one
// non-test caller, in Abort, and no ticker or sweep touched the store. Every
// commit left a full document copy behind for the life of the deployment, and
// store writes are fsynced, so a full disk makes the next commit fail — the
// operation an operator needs when something is already wrong.
func TestCommitPrunesSupersededRecordsButKeepsRollbackDepth(t *testing.T) {
	dir := t.TempDir()
	store, err := openBundleStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	manager := newBundleManager(store, nil)
	document, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}

	// A stage that is never committed must survive every sweep: it is a durable
	// promise the coordinator can come back to.
	if _, err := manager.Stage("bundle-abandoned", document); err != nil {
		t.Fatal(err)
	}

	previous := ""
	ids := []string{}
	for index := 0; index < bundleRetainedGenerations+4; index++ {
		id := fmt.Sprintf("bundle-%04d", index)
		ids = append(ids, id)
		if _, err := manager.Stage(id, document); err != nil {
			t.Fatalf("stage %s: %v", id, err)
		}
		if _, err := manager.Commit(id, previous); err != nil {
			t.Fatalf("commit %s: %v", id, err)
		}
		previous = id
	}

	stored, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]struct{}{}
	for _, id := range stored {
		kept[id] = struct{}{}
	}
	if _, ok := kept["bundle-abandoned"]; !ok {
		t.Fatal("an uncommitted stage was pruned")
	}
	active := ids[len(ids)-1]
	if _, ok := kept[active]; !ok {
		t.Fatalf("the active bundle %s was pruned", active)
	}
	// The pointer's Previous has to remain resolvable: one step back is the
	// rollback a coordinator actually performs.
	ptr, err := store.Pointer()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kept[ptr.Previous]; !ok {
		t.Fatalf("the pointer names Previous=%q but it was pruned", ptr.Previous)
	}
	// active + retained superseded + the abandoned stage.
	if want := bundleRetainedGenerations + 2; len(stored) != want {
		t.Fatalf("store holds %d records (%v), want %d", len(stored), stored, want)
	}
	// And a retained superseded bundle is still committable, which is what the
	// depth is for.
	if _, err := manager.Commit(ptr.Previous, active); err != nil {
		t.Fatalf("rolling back one generation failed: %v", err)
	}
}

// Purge documents that the sidecar "then serves nothing, which mihomo's capture
// rules treat as not-ready and fail closed on". It did not: configStore.Current
// fell through to os.Stat and handed back the pre-migration file, so after a
// coordinator withdrew every bundle the data plane kept intercepting with the
// document the bundle had migrated away from — while GET /state reported nothing
// active.
func TestWithdrawingEveryBundleServesNothingRatherThanTheFile(t *testing.T) {
	fileConfig := validNativeConfig()
	fileConfig.UpstreamProxy.Username = "file-upstream-0000"
	encoded, err := json.Marshal(fileConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := openBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newBundleManager(bundles, nil)
	store.setBundleSource(func() (*Config, bool) { return manager.Active(), manager.Migrated() })

	// Before the first push the file is still the answer. That seam is the whole
	// point of the migration and must survive.
	before, err := store.Current()
	if err != nil {
		t.Fatalf("a deployment that was never pushed a bundle stopped working: %v", err)
	}
	if before.UpstreamProxy.Username != "file-upstream-0000" {
		t.Fatalf("pre-migration config = %q", before.UpstreamProxy.Username)
	}

	document, err := os.ReadFile(filepath.Join("testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Stage("bundle-live", document); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Commit("bundle-live", ""); err != nil {
		t.Fatal(err)
	}
	pushed, err := store.Current()
	if err != nil {
		t.Fatalf("a committed bundle did not serve: %v", err)
	}
	if pushed.UpstreamProxy.Username == "file-upstream-0000" {
		t.Fatal("a committed bundle did not replace the file")
	}
	// One counter serves both sources, so the handover only moves forward.
	if pushed.generation <= before.generation {
		t.Fatalf("generation went from %d to %d across the handover", before.generation, pushed.generation)
	}

	if err := manager.Purge(); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := store.Current()
	if !errors.Is(err, errNoActiveBundle) {
		t.Fatalf("after a purge Current returned %q (err=%v), want errNoActiveBundle",
			withdrawn.UpstreamProxy.Username, err)
	}

	// And the seam stays closed: a later file edit must not resurrect it either.
	fileConfig.UpstreamProxy.Username = "file-upstream-0001"
	edited, err := json.Marshal(fileConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Current(); !errors.Is(err, errNoActiveBundle) {
		t.Fatalf("editing the file after a purge resurrected it: err=%v", err)
	}
}

// A document this build cannot accept is terminal, not retryable.
//
// A decode failure used to be an unclassified error, so the control API
// reported "internal"/500 and the gateway's classifier read that as retryable.
// Repeating a document the sidecar will never accept is a loop, not a recovery,
// and the message that explains it was already in the body under the wrong
// category. The realistic producer is the two hand-maintained validators
// disagreeing about one document inside the same negotiated schema.
func TestUnacceptableDocumentIsTerminal(t *testing.T) {
	t.Parallel()
	store, err := openBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newBundleManager(store, nil)
	_, err = manager.Stage("b-unacceptable", []byte(`{"version":999}`))
	if err == nil {
		t.Fatal("an undecodable document was staged")
	}
	if !errors.Is(err, errBundleInvalidDocument) {
		t.Fatalf("error = %v, want errBundleInvalidDocument so the API reports it as terminal", err)
	}
}
