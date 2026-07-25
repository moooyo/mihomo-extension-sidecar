package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The sidecar's machine-only control API.
//
// This is the interface that replaces "the coordinator writes my private
// configuration file and I poll it". The file made the on-disk layout the
// contract: the coordinator had to know it, neither side could name a version,
// and neither could tell an operator edit from the other's write. An API lets
// the two agree on a bundle identity, on which one is live, and on what
// happened when a response is lost.
//
// Security shape is the same as mihomo's overlay control socket, for the same
// reasons: a unix socket created inside a restrictive umask so it is never
// briefly world-writable, peer credentials checked on every accept rather than
// once at startup, no CORS, and no-store on every response.

const (
	// controlAPISchema is the version this build speaks. A coordinator that
	// does not understand it must refuse rather than guess.
	controlAPISchema = 1

	controlMaxRequestBytes = 32 << 20
	controlReadTimeout     = 30 * time.Second
	controlWriteTimeout    = 30 * time.Second
)

// controlServer serves the control API.
type controlServer struct {
	manager *bundleManager
	version string
	// peerUID and peerGID restrict which local process may connect. A negative
	// value means unrestricted, which is only defensible because the socket is
	// 0600 inside a 0700 directory owned by this process's user.
	peerUID int
	peerGID int

	srv *http.Server
}

func newControlServer(manager *bundleManager, version string, peerUID, peerGID int) *controlServer {
	return &controlServer{manager: manager, version: version, peerUID: peerUID, peerGID: peerGID}
}

// Serve binds the socket and serves until the listener closes.
func (c *controlServer) Serve(path string) error {
	l, err := listenControlSocket(path, c.peerUID, c.peerGID)
	if err != nil {
		return err
	}
	c.srv = &http.Server{
		Handler:      c.routes(),
		ReadTimeout:  controlReadTimeout,
		WriteTimeout: controlWriteTimeout,
	}
	log.Printf("intercept: control API listening at %s", path)
	err = c.srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server.
func (c *controlServer) Close() error {
	if c.srv == nil {
		return nil
	}
	return c.srv.Close()
}

func (c *controlServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /capabilities", c.handleCapabilities)
	mux.HandleFunc("GET /state", c.handleState)
	mux.HandleFunc("GET /plugins", c.handlePlugins)
	mux.HandleFunc("PUT /bundles/{id}", c.handleStage)
	mux.HandleFunc("POST /bundles/{id}/commit", c.handleCommit)
	mux.HandleFunc("POST /bundles/{id}/abort", c.handleAbort)
	mux.HandleFunc("DELETE /bundles", c.handlePurge)
	return noStoreHeaders(mux)
}

// noStoreHeaders marks every response uncacheable. These carry the live bundle
// identity and the process instance; a cached one is a stale one, and a stale
// one is what a coordinator must never act on.
func noStoreHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

type controlError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *controlServer) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps an error onto a stable code so the coordinator can branch on
// the outcome rather than parse prose.
func (c *controlServer) writeError(w http.ResponseWriter, err error) {
	code, status := "internal", http.StatusInternalServerError
	switch {
	case errors.Is(err, errBundleNotFound):
		code, status = "not_found", http.StatusNotFound
	case errors.Is(err, errBundleConflict):
		code, status = "cas_conflict", http.StatusConflict
	case errors.Is(err, errBundleWrongState):
		code, status = "wrong_state", http.StatusConflict
	case errors.Is(err, errBundleSchema):
		code, status = "unsupported_schema", http.StatusBadRequest
	case errors.Is(err, errBundleCorrupt):
		code, status = "store_corrupt", http.StatusInternalServerError
	}
	c.writeJSON(w, status, controlError{Code: code, Message: err.Error()})
}

type capabilitiesResponse struct {
	Schema   int               `json:"schema"`
	Version  string            `json:"version"`
	Instance string            `json:"instanceId"`
	Features map[string]int    `json:"features"`
	Limits   map[string]int    `json:"limits"`
	Paths    map[string]string `json:"paths"`
}

func (c *controlServer) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	c.writeJSON(w, http.StatusOK, capabilitiesResponse{
		Schema:   controlAPISchema,
		Version:  c.version,
		Instance: c.manager.InstanceID(),
		Features: map[string]int{
			"bundles":     1,
			"plugins":     1,
			"engine-logs": 1,
		},
		Limits: map[string]int{"maxBundleBytes": controlMaxRequestBytes},
		Paths:  map[string]string{"store": c.manager.store.Dir()},
	})
}

func (c *controlServer) handleState(w http.ResponseWriter, r *http.Request) {
	c.writeJSON(w, http.StatusOK, c.manager.Readback(c.version))
}

func (c *controlServer) handlePlugins(w http.ResponseWriter, r *http.Request) {
	c.writeJSON(w, http.StatusOK, map[string]any{
		"activeBundle": c.manager.ActiveID(),
		"plugins":      c.manager.Plugins(),
	})
}

type stageResponse struct {
	BundleID string `json:"bundleId"`
	Digest   string `json:"digest"`
}

func (c *controlServer) handleStage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, err := io.ReadAll(io.LimitReader(r.Body, controlMaxRequestBytes))
	if err != nil {
		c.writeError(w, fmt.Errorf("read body: %w", err))
		return
	}
	digest, err := c.manager.Stage(id, body)
	if err != nil {
		c.writeError(w, err)
		return
	}
	c.writeJSON(w, http.StatusOK, stageResponse{BundleID: id, Digest: digest})
}

type commitRequest struct {
	ExpectedActiveBundle string `json:"expectedActiveBundle"`
}

type commitResponse struct {
	BundleID   string `json:"bundleId"`
	Digest     string `json:"digest"`
	Generation uint64 `json:"generation"`
}

func (c *controlServer) handleCommit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req commitRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			c.writeError(w, fmt.Errorf("decode body: %w", err))
			return
		}
	}
	digest, err := c.manager.Commit(id, req.ExpectedActiveBundle)
	if err != nil {
		c.writeError(w, err)
		return
	}
	var generation uint64
	if cfg := c.manager.Active(); cfg != nil {
		generation = cfg.generation
	}
	c.writeJSON(w, http.StatusOK, commitResponse{BundleID: id, Digest: digest, Generation: generation})
}

func (c *controlServer) handleAbort(w http.ResponseWriter, r *http.Request) {
	if err := c.manager.Abort(r.PathValue("id")); err != nil {
		c.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *controlServer) handlePurge(w http.ResponseWriter, r *http.Request) {
	if err := c.manager.Purge(); err != nil {
		c.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listenControlSocket binds a unix socket with a restrictive mode and wraps it
// in a peer-verifying listener.
//
// The mode comes from a narrowed umask around the bind rather than a chmod
// afterwards, so the socket is never briefly reachable with whatever umask the
// process happened to inherit.
func listenControlSocket(path string, peerUID, peerGID int) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("control socket: create %s: %w", dir, err)
	}
	// A stale socket from a previous process would make bind fail. Removing it
	// is safe because the directory is 0700 and owned by this user.
	if err := syscall.Unlink(path); err != nil && !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
		log.Printf("intercept: control socket unlink %s: %v", path, err)
	}

	restore := narrowUmask()
	l, err := net.Listen("unix", path)
	restore()
	if err != nil {
		return nil, fmt.Errorf("control socket: listen %s: %w", path, err)
	}
	return &peerVerifiedListener{Listener: l, uid: peerUID, gid: peerGID, path: path}, nil
}

// peerVerifiedListener checks the connecting process on every accept.
//
// Per connection, not once: the socket outlives any single peer, and a check at
// bind time proves nothing about who connects later.
type peerVerifiedListener struct {
	net.Listener
	uid  int
	gid  int
	path string
}

func (l *peerVerifiedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.uid < 0 && l.gid < 0 {
			return conn, nil
		}
		uid, gid, err := connPeerCredentials(conn)
		if err != nil {
			log.Printf("intercept: control socket %s: cannot identify peer, closing: %v", l.path, err)
			_ = conn.Close()
			continue
		}
		if l.uid >= 0 && uid != l.uid {
			log.Printf("intercept: control socket %s: rejected peer uid %d (want %d)", l.path, uid, l.uid)
			_ = conn.Close()
			continue
		}
		if l.gid >= 0 && gid != l.gid {
			log.Printf("intercept: control socket %s: rejected peer gid %d (want %d)", l.path, gid, l.gid)
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
