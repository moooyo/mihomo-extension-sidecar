# 5gpn-intercept

`5gpn-intercept` is the allowlisted transformation sidecar for explicitly
enabled interception modules. It is not an open proxy and does not fetch module
or script content at runtime.

The service accepts authenticated SOCKS5 on `127.0.0.1:18080`. TCP CONNECT is
terminated as TLS with HTTP/1.1 and HTTP/2 support. An authenticated UDP
ASSOCIATE receives a private ephemeral loopback socket and is terminated as
QUIC v1/v2 with HTTP/3. A hostname target and the eventual TLS/QUIC SNI must
match the active module host set. Pure-IP SOCKS targets are accepted only until
the authenticated application handshake supplies an allowlisted SNI.

Every upstream connection returns through the authenticated mihomo mixed
listener at `127.0.0.1:17890`. TCP uses SOCKS5 CONNECT and HTTP/3 uses a custom
SOCKS5 UDP `net.PacketConn`; the sidecar has no direct origin egress path. The
HTTP/3 client prefers QUIC v1 and retries v2 only on version negotiation before
request transmission.

External Surge and Loon modules arrive as bounded immutable JSON snapshots in
`/etc/5gpn/intercept/config.json`. The runtime supports normalized MITM hosts,
HTTP request/response JavaScript actions, request-header rewrites, and terminal
URL reject/redirect actions. Every action runs in a fresh goja VM with bounded source/body sizes,
execution time, and backtracking-regexp time. There is no script network,
filesystem, process, or module-loader access. `$persistentStore` and `$prefs`
write only to the bounded service-owned
`/var/lib/5gpn-intercept/store.json`.

The built-in WLOC module buffers `/clls/wloc` responses up to its configured
limit, optionally decompresses gzip, structurally patches the protobuf payload,
and returns it without logging coordinates or payload bytes. Its default
failure mode is closed.

The runtime leaf must be a non-CA certificate covering the stable WLOC names
and all enabled external-module patterns. The sidecar cannot access the private
root CA signing key. The root-owned certificate publisher derives the canonical
SAN list from the validated sidecar binary and acknowledges its digest through
`/etc/5gpn/intercept/cert-state`.

Useful commands:

```text
5gpn-intercept --version
5gpn-intercept --config /etc/5gpn/intercept/config.json --check-config
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-hosts
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-digest
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-request
5gpn-intercept --config /etc/5gpn/intercept/config.json --healthcheck
```
