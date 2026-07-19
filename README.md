# 5gpn-intercept

`5gpn-intercept` is the allowlisted transformation sidecar for explicitly
enabled interception modules. It is not an open proxy and does not fetch module
or script content at runtime.

The service remains stopped unless the version-2 configuration's MITM master is
enabled. It then accepts authenticated SOCKS5 on `127.0.0.1:18080`. TCP CONNECT
on port 80 serves plain HTTP; port 443 terminates TLS with HTTP/1.1 and,
optionally, HTTP/2. An authenticated UDP
ASSOCIATE receives a private ephemeral loopback socket. It either terminates
IETF QUIC v1/v2 with HTTP/3 or discards matched packets for client TCP fallback,
according to `quic_fallback_protection`. Legacy GQUIC is not claimed. A
hostname target and the eventual TLS/QUIC SNI must
match the active module host set. Pure-IP SOCKS targets are accepted only until
the authenticated application handshake supplies an allowlisted SNI.

Every upstream connection returns through the authenticated mihomo mixed
listener at `127.0.0.1:17890`. TCP uses SOCKS5 CONNECT and HTTP/3 uses a custom
SOCKS5 UDP `net.PacketConn`; the sidecar has no direct origin egress path. The
HTTP/3 client prefers QUIC v1 and retries v2 only on version negotiation before
request transmission.

External Loon modules arrive as bounded immutable JSON snapshots in
`/etc/5gpn/intercept/config.json`. The runtime supports normalized MITM hosts,
HTTP request/response JavaScript actions, Loon URL/header rewrites, module Host
mappings, and post-import input/select parameters. Every action runs in a fresh
goja VM with bounded source/body sizes,
execution time, and backtracking-regexp time. There is no script network,
filesystem, process, or module-loader access. String and Uint8Array bodies
decode identity, gzip, deflate, and Brotli within expanded-size limits.
`$persistentStore` writes only to the bounded service-owned
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
5gpn-intercept --config /etc/5gpn/intercept/config.json --check-enabled
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-hosts
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-digest
5gpn-intercept --config /etc/5gpn/intercept/config.json --print-certificate-request
5gpn-intercept --config /etc/5gpn/intercept/config.json --healthcheck
```
