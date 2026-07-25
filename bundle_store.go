package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// The sidecar's own durable bundle store.
//
// Before this, the coordinator wrote the sidecar's private configuration file
// and the sidecar polled it. That made the file the interface: the coordinator
// had to know the sidecar's on-disk layout, the sidecar could not tell an
// operator edit from a coordinator write, and neither side could say which
// bundle the other believed was live. The sidecar now owns its state and the
// coordinator pushes to an API.
//
// The durability rules are the same ones the runtime overlay needs and for the
// same reason: a bundle is an authorization boundary, so a half-written one has
// no safe interpretation.

// bundleStoreSchema versions the on-disk layout. A store written by a newer
// build is refused, never repaired — a downgrade must be a deliberate purge.
const bundleStoreSchema = 1

const (
	bundleMetaFile    = "meta.json"
	bundlePointerFile = "pointer.json"
	bundlesDir        = "bundles"
	bundleSuffix      = ".json"
	bundleTempSuffix  = ".tmp"
)

var (
	// errBundleNotFound means the named bundle is not in the store.
	errBundleNotFound = errors.New("bundle not found")
	// errBundleWrongState means the operation is illegal from the bundle's
	// current state.
	errBundleWrongState = errors.New("bundle is in the wrong state")
	// errBundleConflict means a compare-and-swap precondition did not hold.
	errBundleConflict = errors.New("bundle compare-and-swap conflict")
	// errBundleCorrupt means a stored artifact failed its own digest check.
	errBundleCorrupt = errors.New("bundle store is corrupt")
	// errBundleSchema means the artifact was written by a schema this build
	// does not understand.
	errBundleSchema = errors.New("unsupported bundle schema")
)

type bundleState string

const (
	// bundleStaged is persisted and decodable but not serving traffic.
	bundleStaged bundleState = "STAGED"
	// bundleActive is the one the sidecar compiles and runs.
	bundleActive bundleState = "ACTIVE"
	// bundleSuperseded is retained for one generation so a rollback does not
	// need the coordinator to re-upload it.
	bundleSuperseded bundleState = "SUPERSEDED"
)

// bundleRecord is one durable bundle artifact.
type bundleRecord struct {
	Schema      int         `json:"schema"`
	ID          string      `json:"id"`
	State       bundleState `json:"state"`
	Digest      string      `json:"digest"`
	Document    []byte      `json:"document"`
	StagedAt    int64       `json:"stagedAt"`
	ActivatedAt int64       `json:"activatedAt,omitempty"`
	// RecordDigest covers every field above, so a tampered document with a
	// stale digest field cannot pass.
	RecordDigest string `json:"recordDigest"`
}

func (r *bundleRecord) computeRecordDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "bundle-record/v1\x00%d\x00%s\x00%s\x00%s\x00%d\x00%d\x00",
		r.Schema, r.ID, r.State, r.Digest, r.StagedAt, r.ActivatedAt)
	h.Write(r.Document)
	return hex.EncodeToString(h.Sum(nil))
}

// bundlePointer is the durable record of which bundle to load at startup.
type bundlePointer struct {
	Schema    int    `json:"schema"`
	Active    string `json:"active"`
	Previous  string `json:"previous,omitempty"`
	UpdatedAt int64  `json:"updatedAt"`
	Digest    string `json:"digest"`
}

func (p *bundlePointer) computeDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "bundle-pointer/v1\x00%d\x00%s\x00%s\x00%d", p.Schema, p.Active, p.Previous, p.UpdatedAt)
	return hex.EncodeToString(h.Sum(nil))
}

type bundleStoreMeta struct {
	Schema    int   `json:"schema"`
	CreatedAt int64 `json:"createdAt"`
}

// bundleStore is the sidecar's durable state.
type bundleStore struct {
	mu  sync.Mutex
	dir string
}

// openBundleStore prepares the store directory.
func openBundleStore(dir string) (*bundleStore, error) {
	if dir == "" {
		return nil, errors.New("bundle store: empty directory")
	}
	if err := os.MkdirAll(filepath.Join(dir, bundlesDir), 0o700); err != nil {
		return nil, fmt.Errorf("bundle store: create %s: %w", dir, err)
	}
	s := &bundleStore{dir: dir}

	metaPath := filepath.Join(dir, bundleMetaFile)
	raw, err := os.ReadFile(metaPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		m := bundleStoreMeta{Schema: bundleStoreSchema, CreatedAt: time.Now().Unix()}
		if err := s.writeJSON(metaPath, &m); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("bundle store: read metadata: %w", err)
	default:
		var m bundleStoreMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: metadata is unreadable: %s", errBundleCorrupt, err)
		}
		if m.Schema != bundleStoreSchema {
			return nil, fmt.Errorf("%w: store schema is %d, this build understands %d; purge before downgrading",
				errBundleSchema, m.Schema, bundleStoreSchema)
		}
	}
	return s, nil
}

// Dir reports the store root.
func (s *bundleStore) Dir() string { return s.dir }

func (s *bundleStore) bundlePath(id string) (string, error) {
	if err := validateBundleID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, bundlesDir, id+bundleSuffix), nil
}

// validateBundleID bounds the identifier because it becomes a filename.
func validateBundleID(id string) error {
	if id == "" {
		return errors.New("bundle id is empty")
	}
	if len(id) > 128 {
		return errors.New("bundle id exceeds 128 bytes")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("bundle id contains an illegal byte %q; allowed are [A-Za-z0-9._-]", string(c))
		}
	}
	if id == "." || id == ".." || strings.HasPrefix(id, ".") {
		return fmt.Errorf("bundle id %q is not a usable path segment", id)
	}
	return nil
}

// Put writes a bundle artifact durably.
func (s *bundleStore) Put(rec *bundleRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.bundlePath(rec.ID)
	if err != nil {
		return err
	}
	rec.Schema = bundleStoreSchema
	rec.RecordDigest = rec.computeRecordDigest()
	return s.writeJSON(path, rec)
}

// Get loads a bundle and verifies its integrity.
func (s *bundleStore) Get(id string) (*bundleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(id)
}

func (s *bundleStore) getLocked(id string) (*bundleRecord, error) {
	path, err := s.bundlePath(id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", errBundleNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("bundle store: read %s: %w", id, err)
	}
	var rec bundleRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("%w: bundle %s is unreadable: %s", errBundleCorrupt, id, err)
	}
	if rec.Schema != bundleStoreSchema {
		return nil, fmt.Errorf("%w: bundle %s uses schema %d", errBundleSchema, id, rec.Schema)
	}
	if rec.RecordDigest != rec.computeRecordDigest() {
		return nil, fmt.Errorf("%w: bundle %s failed its integrity check", errBundleCorrupt, id)
	}
	if rec.ID != id {
		return nil, fmt.Errorf("%w: bundle %s contains id %q", errBundleCorrupt, id, rec.ID)
	}
	return &rec, nil
}

// Delete removes a bundle. A missing bundle is not an error, so garbage
// collection can be retried freely.
func (s *bundleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.bundlePath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bundle store: delete %s: %w", id, err)
	}
	return syncBundleDir(filepath.Dir(path))
}

// List returns every stored bundle id, sorted.
func (s *bundleStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(filepath.Join(s.dir, bundlesDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bundle store: list: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, bundleSuffix) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, bundleSuffix))
	}
	sort.Strings(out)
	return out, nil
}

// Pointer loads the startup pointer. A missing pointer is the valid empty
// state, not an error.
func (s *bundleStore) Pointer() (*bundlePointer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(filepath.Join(s.dir, bundlePointerFile))
	if errors.Is(err, os.ErrNotExist) {
		return &bundlePointer{Schema: bundleStoreSchema}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bundle store: read pointer: %w", err)
	}
	var p bundlePointer
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: pointer is unreadable: %s", errBundleCorrupt, err)
	}
	if p.Schema != bundleStoreSchema {
		return nil, fmt.Errorf("%w: pointer uses schema %d", errBundleSchema, p.Schema)
	}
	if p.Digest != p.computeDigest() {
		return nil, fmt.Errorf("%w: pointer failed its integrity check", errBundleCorrupt)
	}
	return &p, nil
}

// SetPointer writes the startup pointer.
func (s *bundleStore) SetPointer(p *bundlePointer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.Schema = bundleStoreSchema
	p.UpdatedAt = time.Now().Unix()
	p.Digest = p.computeDigest()
	return s.writeJSON(filepath.Join(s.dir, bundlePointerFile), p)
}

// Purge removes every artifact. It is the downgrade contract's purge step:
// artifacts left behind would let a later upgrade resurrect a bundle the
// operator believes was withdrawn.
func (s *bundleStore) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.RemoveAll(filepath.Join(s.dir, bundlesDir)); err != nil {
		return fmt.Errorf("bundle store: purge bundles: %w", err)
	}
	if err := os.Remove(filepath.Join(s.dir, bundlePointerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bundle store: purge pointer: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s.dir, bundlesDir), 0o700); err != nil {
		return fmt.Errorf("bundle store: recreate: %w", err)
	}
	return syncBundleDir(s.dir)
}

// writeJSON writes atomically: temp file, fsync, rename, fsync directory.
func (s *bundleStore) writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle store: encode %s: %w", filepath.Base(path), err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	tmp := path + bundleTempSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("bundle store: create %s: %w", tmp, err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("bundle store: write %s: %w", tmp, err)
	}
	// fsync before rename: the store exists to survive the crash that loses an
	// in-flight commit, and an unsynced write does not.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("bundle store: fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("bundle store: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("bundle store: publish %s: %w", path, err)
	}
	return syncBundleDir(dir)
}

// syncBundleDir fsyncs a directory so the rename itself is durable. Windows
// cannot open a directory as a file and journals its renames, so it is skipped
// there rather than failing every write; the gateway is Linux.
func syncBundleDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("bundle store: open %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("bundle store: fsync %s: %w", dir, err)
	}
	return nil
}
