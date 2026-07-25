# 5gpn-intercept

`5gpn-intercept` is the allowlisted transformation sidecar for explicitly
enabled native interception extensions. It is not an open proxy and does not fetch extension
or script content at runtime.

The service remains stopped unless the version-5 configuration's MITM master
and at least one extension are enabled. It then accepts authenticated SOCKS5 on `127.0.0.1:18080`. TCP CONNECT
on port 80 serves plain HTTP; port 443 terminates TLS with HTTP/1.1 and,
optionally, HTTP/2. An authenticated UDP
ASSOCIATE receives a private ephemeral loopback socket. It either terminates
IETF QUIC v1/v2 with HTTP/3 or discards matched packets for client TCP fallback,
according to `quic_fallback_protection`. Legacy GQUIC is not claimed. A
hostname target and the eventual TLS/QUIC SNI must
match the active extension capture-host set. Pure-IP SOCKS targets are accepted only until
the authenticated application handshake supplies an allowlisted SNI.

Every upstream connection returns through the authenticated mihomo mixed
listener at `127.0.0.1:17890`. TCP uses SOCKS5 CONNECT and HTTP/3 uses a custom
SOCKS5 UDP `net.PacketConn`; the sidecar has no direct origin egress path. The
HTTP/3 client prefers QUIC v1 and retries v2 only on version negotiation before
request transmission.

Native `5gpn.io/v1` manifests are compiled by `5gpn-dns` into bounded immutable
JSON snapshots in `/etc/5gpn/intercept/config.json`. The sidecar receives only
normalized capture hosts, structured action matchers, typed settings, explicit
permissions, exact approved network origins, safe upstream mappings, operator
egress bindings, explicit execution order, and immutable scripts. Every action runs
in a fresh goja VM through `transform(context)` with bounded source/body sizes,
execution time, and backtracking-regexp time. There is no ambient network,
filesystem, process, timer, or module-loader access. A module that declared
network origins receives synchronous `context.network.request` and may return a
request-phase URL rewrite to one of those same exact origins. Cross-origin
rewrites require a canonical absolute URL, cannot contain userinfo or a
fragment, and cannot downgrade an intercepted HTTPS request to HTTP. They keep
the request method, decoded body, and end-to-end headers; consequently Cookie,
Authorization, and any other visible credentials may be sent to the reviewed
origin. Framing and hop-by-hop headers remain runtime-owned. Both explicit
network calls and rewritten requests return through the authenticated upstream
mihomo SOCKS5 listener. Ambient `fetch` and sockets remain unavailable. String
and Uint8Array bodies decode identity, gzip, deflate, and Brotli within
expanded-size limits. When explicitly permitted, `context.storage` writes only
to the bounded service-owned `/var/lib/5gpn-intercept/store.json`.

Structured script-console output and action lifecycle events are retained only
in a 1000-entry in-memory ring; arbitrary script console text is never written
to journald. The sidecar exposes that live, read-only stream on the fixed
`/run/5gpn-intercept/logs.sock` Unix socket. The socket is mode `0660` inside a
systemd-owned mode-`0750` runtime directory and serves only `GET /health` plus
the RFC 6455 `GET /logs` upgrade. At most eight log WebSockets may be active;
new connections start at the current tail and never replay disconnected data.
URL metadata strips userinfo, query strings, and fragments. No TCP log
listener, disk log, or additional dependency is used. Log IPC failure is
non-fatal to the interception data plane.

The runtime leaf must be a non-CA certificate covering only enabled native
extension capture-host patterns. The sidecar cannot access the private
root CA signing key. The root-owned certificate publisher derives the canonical
SAN list from the validated sidecar binary and acknowledges its digest through
`/etc/5gpn/intercept/cert-state`.

Useful commands:

```text
5gpn-intercept --version
5gpn-intercept --config /etc/5gpn/intercept/config.json --check-config
5gpn-intercept --config /etc/5gpn/intercept/config.json --check-enabled
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-hosts
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-digest
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-request
5gpn-intercept --config /etc/5gpn/intercept/config.json --healthcheck
```

## Control API

The sidecar is a separately-versioned component: 5gpn drives it through an API
and no longer reaches into its state. Its Go module is
`github.com/moooyo/5gpn-intercept`, nothing in 5gpn imports it, and the only
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
`/var/lib/5gpn-intercept`). Bundles are written with atomic rename, an fsync of
both the file and its directory, and a per-record integrity digest. A store
written by a newer schema is refused rather than repaired, so a downgrade has to
be a deliberate purge.

On restart it reloads the bundle it was serving. An unusable artifact is logged
and skipped rather than fatal: serving nothing is the safe state, because
mihomo's capture rules treat a processor with no bundle as not ready and fail
closed on it.

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
