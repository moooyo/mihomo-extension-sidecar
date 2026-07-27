# 5gpn-intercept

The allowlisted transformation sidecar, maintained independently of the gateway
that drives it.

It was extracted from `moooyo/5gpn` — first as `cmd/5gpn-intercept`, then as
`plugin-sidecar/` — and this repository carries that history. The split is not
cosmetic: the sidecar and the gateway share no Go types, only a versioned
control-API wire format, so the thing that keeps them working together is a
schema number rather than a compiler. Separating the repositories makes that
boundary the only one there is.

The binary, the service name and the runtime paths stay `5gpn-intercept`. They
are what installed gateways and their unit files refer to, and the Go module
path is the only identifier that follows the repository.

## Control API

The sidecar is a separately-versioned component: 5gpn drives it through an API
and no longer reaches into its state. Its Go module is
`github.com/moooyo/mihomo-extension-sidecar`, nothing in 5gpn imports it, and the only
things crossing the boundary are this API, the SOCKS legs and the certificate
artifacts — so extracting this directory into its own repository later is a
move, not a rewrite.

The API is a machine-only `AF_UNIX` socket, default
`/run/5gpn-intercept/control.sock`. It is created inside a narrowed umask so it
is never briefly reachable with whatever umask the process inherited, peer
credentials are checked on **every** accept rather than once at startup, and
every response is `no-store` — these carry the live bundle identity and the
process instance, so a cached answer is a wrong answer.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/capabilities` | schema version, build version, process instance, limits |
| `GET` | `/state` | authoritative readback: active bundle, digest, generation, extension and capture-host counts |
| `GET` | `/plugins` | per-extension view for the console: name, version, capture hosts, action and setting counts, execution order |
| `PUT` | `/bundles/{id}` | stage an immutable bundle; returns its digest |
| `POST` | `/bundles/{id}/commit` | make it live, compare-and-swap against the bundle the caller believes is active |
| `POST` | `/bundles/{id}/abort` | discard a staged bundle |
| `DELETE` | `/bundles` | purge all state |

Errors carry a stable `code` so a coordinator branches on the outcome instead of
parsing prose: `not_found`, `cas_conflict`, `wrong_state`,
`unsupported_schema`, `store_corrupt`, `internal`.

### Why staging and commit are separate

A staged bundle is durable and validated but serves nothing. That is what makes
preparation safe to retry: the coordinator can stage speculatively, wait for a
certificate, and only then commit — and if it crashes in between, nothing it
prepared was ever live.

Commit carries the bundle the caller believes is active and refuses if that is
not what is live. A repeat of a commit that already succeeded returns the same
success rather than a conflict, because a coordinator that lost the response
must be able to roll forward instead of rolling back something already serving
traffic.

## State ownership

The sidecar owns its state under `--bundle-store` (default
`/var/lib/5gpn-intercept`): both the bundles and the extensions' persistent
storage, so moving the flag moves all of it. Bundles are written with atomic
rename, an fsync of both the file and its directory, and a per-record integrity
digest. A store written by a newer schema is refused rather than repaired, so a
downgrade has to be a deliberate purge.

On restart it reloads the bundle it was serving. An unusable artifact is logged
and skipped rather than fatal: serving nothing is the safe state, because
mihomo's capture rules treat a processor with no bundle as not ready and fail
closed on it.

### The sidecar does not consult a mihomo generation socket

Revocation is a push. A bundle stops being served when the coordinator commits a
different one or calls `DELETE /bundles`, and mihomo fails closed on a processor
that reports none. There is no second opinion asked of the gateway at request
time.

This is worth stating because the repository once claimed otherwise. Commit
`658b400` said "the processor now resolves the generation it is allowed to work
under from mihomo's read-only generation socket, at every boundary", and added a
`mihomo_generation.go` that implemented exactly that. Nothing ever called it, and
nothing ever created the socket it dialled — the commit added those two files and
changed nothing else. The design it belonged to was replaced by this component
owning its own bundle store, so the file has been deleted rather than wired up:
wiring it up would reintroduce the second commit point the file itself forbade,
and its `capture()` treats an unreadable socket as a refusal, so enabling it
against a socket no one creates would fail closed on every request.

Two functions that look similarly unused are **not** dead and must not be
removed: `activeModuleUpstreamTarget` and `mappedInterceptTarget` have no
production caller because production dialling goes through
`upstreamTargetProjection`, but they are the naive reference implementation that
`transport_projection_test.go` differentially tests the compiled matcher against.
Deleting them removes the only cross-check between the two allowlist
implementations.

### Migration from the file

Before this API, 5gpn wrote the sidecar's private configuration file and the
sidecar polled it. That made the on-disk layout the contract: the coordinator
had to know it, neither side could name a version, and neither could tell an
operator edit from the other's write.

A deployment that has never been pushed a bundle keeps using the file exactly as
before. The first successful commit flips the source permanently, so the two
never both decide; there is no window in which the file and a pushed bundle
disagree. `--control-socket ""` disables the API entirely and is the rollback
position.

```text
5gpn-intercept \
  --config /etc/5gpn/intercept/config.json \
  --bundle-store /var/lib/5gpn-intercept \
  --control-socket /run/5gpn-intercept/control.sock \
  --control-peer-uid "$(id -u gpn-dns)"
```

## Tests

```sh
gofmt -l . && go vet ./... && go test -race ./...
```

`testdata/bundle.json` is derived from real operator state rather than
hand-written, because a hand-written fixture only exercises the fields whoever
wrote it remembered.
