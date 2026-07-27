# Proxy-client compatibility layer

## Goal

Run upstream proxy-client bundles (for example
`NSRingo/WeatherKit`'s `response.bundle.js`) directly, instead of hand-porting a
slice of their behavior into a native `transform(context)` script. The current
port covers roughly 5% of that bundle's features and needs a manual review cycle
for every upstream release; running the bundle removes both costs.

Two things block it today. The first — async — is solved by `module_async.go`.
This document specifies the second: the `$` globals the bundles expect.

## What the bundle actually needs

Measured against `v3.2.0-beta2/response.bundle.js` (251,617 bytes):

| Global | References | Purpose |
| --- | ---: | --- |
| `$argument` | 12 | Settings, as a serialized string it parses itself |
| `$done` | 5 | Completion; receives the final response projection |
| `$persistentStore` | 4 | `read(key)` / `write(value, key)` |
| `$prefs` | 4 | Quantumult X storage; unused under the Surge persona |
| `$response` | 3 | Response projection, mutated in place |
| `$request` | 2 | Request projection |
| `$task` | 2 | Quantumult X fetch; **must not be defined** (see below) |
| `$environment` | 2 | Runtime identity |
| `$httpClient` | 1 | Surge-style network |

Async surface: 31 `async`, 57 `await`, 8 `Promise`, 2 `setTimeout`.

All 6 `require(` sites sit behind a `"Node.js"` runtime branch, so **no module
loader is needed**. Both `setTimeout` sites race a pending request against a
timeout, which `module_async.go` already provides.

## Persona: Surge

`@nsnanocat/util` picks its runtime by probing globals, in this order:

```js
switch (true) {
  case "$task" in globalThis:     return "Quantumult X"
  case "$loon" in globalThis:     return "Loon"
  case "$rocket" in globalThis:   return "Shadowrocket"
  case "Egern" in globalThis:     return "Egern"
  case Boolean(globalThis.$environment?.["surge-version"]): return "Surge"
  case Boolean(globalThis.$environment?.["stash-version"]):  return "Stash"
  ...
}
```

Presenting as **Surge** means defining `$environment["surge-version"]` and
**not** defining `$task`, `$loon`, `$rocket`, or `Egern`. Surge is the right
persona because its network shape is a plain callback
(`$httpClient[method](options, cb)`) that maps directly onto the sidecar's
existing requester, and its storage shape is two functions.

## Entry and exit model

This is the part that differs most from the native contract. The bundle's entry
point is not a function that returns a value:

```js
(async () => { $response = await Response($request, $response) })()
  .catch(error => log.error(error))
  .finally(() => done($response))
```

and the Surge branch of `done` is:

```js
case "Surge":
  s.policy && _.set(s, "headers.X-Surge-Policy", s.policy)
  log("🚩 执行结束!", `🕛 ${(new Date).getTime() / 1e3 - $script.startTime} 秒`)
  $done(s)
```

So the runtime must:

1. run the program, which returns immediately with async work pending;
2. drive the event loop until `$done` is called or the action deadline expires;
3. treat the value passed to `$done` as the action result.

`$script.startTime` must exist — the Surge branch reads it before calling
`$done`, and a `TypeError` there would be swallowed by `.finally()` and hang the
action until its deadline.

`asyncLoop.wait` already accepts an arbitrary `settled` predicate, so compat mode
passes `func() bool { return doneCalled }` where native mode passes the promise
state. No second loop is needed.

## Global shapes

```
$environment      { "surge-version": <string> }
$script           { startTime: <seconds, float> }
$request          { url, method, headers, body? }
$response         { status, statusCode, headers, body | bodyBytes }
$done(result)     result: { status?, headers?, body? | bodyBytes? }
$persistentStore  { read(key) -> string|null, write(value, key) -> bool }
$httpClient       { get|post|put|delete|head|patch(options, cb) }
                  cb(error, response, body); response.status, response.headers
$argument         string, "key=value&key=value", parsed by the bundle itself
```

Binary bodies: the sgmodule sets `binary-body-mode=1`, and the util normalizes
`bodyBytes` into `body` before a request and mirrors a binary response body into
both fields. The sidecar's existing `bodyMode: binary` projection supplies the
`Uint8Array`.

`$argument` must be serialized from typed manifest settings into the
`key="value"&key="value"` form the published sgmodule uses, because the bundle
runs its own parser over the string.

## Mapping onto existing sidecar capabilities

| Global | Backed by |
| --- | --- |
| `$httpClient` | `moduleNetworkRequester.request`, run on a worker goroutine, completion posted through `asyncLoop.post` |
| `$persistentStore` | `scriptRuntime.storageObject`, already bounded and extension-scoped |
| `$request` / `$response` | `scriptMessageObject`, unchanged |
| `$argument` | `scriptSettingValues`, serialized |
| console | `installConsoleAPI`, unchanged |

Only `$httpClient` needs new plumbing, and only to move a blocking call off the
VM goroutine — the request validation, origin check, concurrency slots, body
bounds, and SOCKS5 egress are all reused as-is.

## Required contract changes

These are policy decisions, not runtime mechanics:

1. **Network as a capability, not an origin list.** `permissions.network.origins`
   cannot express `API.QWeather.Host`, which the operator sets to an arbitrary
   host. The bundle also reaches several provider APIs. Replace the exact
   allowlist with a declared network capability. A denylist is still worth
   keeping so the gateway's own reject rules cannot be undone from inside a
   script.
2. **Remote scripts.** The bundle is published per release. The control plane
   already fetches and snapshots script bodies, so the cheap change is to relax
   the review cycle rather than to give the sidecar a fetch path. Recording the
   digest on first install and prompting when it changes (trust on first use)
   keeps a silent swap visible without reintroducing per-file review — GitHub
   reports `immutable: false` for these release assets, so they can be replaced
   in place.
3. **Entry-point selection.** A manifest needs to say which contract a script
   uses. Compat mode changes the completion model, so it cannot be inferred
   safely from the source.

## Status

- `module_async.go` — implemented and tested: event loop, promise settling,
  timers, budget, deadline behavior.
- Compat globals — specified here, not yet implemented.
- Contract changes — not started; they touch `5gpn-dns` and the Console.
