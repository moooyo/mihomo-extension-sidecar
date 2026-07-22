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
