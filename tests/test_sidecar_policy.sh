#!/usr/bin/env bash
# Policy assertions about this component's own source.
#
# They used to live in the gateway's tests/test_intercept_policy.sh, addressing
# this code through a plugin-sidecar/ subdirectory. That is what carrying a copy
# of a component inside its consumer looks like: the consumer's test suite is
# where the component's invariants are enforced, so the component cannot be
# changed, reviewed or released on its own.
#
# They are the same assertions, rooted here.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIDECAR_CONFIG="$ROOT/config.go"
SIDECAR_LOGS="$ROOT/engine_logs.go"
SIDECAR_RUNTIME="$ROOT/module_runtime.go"
SIDECAR_MAIN="$ROOT/main.go"
SIDECAR_PROXY="$ROOT/proxy.go"
rc=0
fail() { echo "FAIL: $1"; rc=1; }

[[ -f "$ROOT/go.mod" ]] || fail "interception Go module is missing"
grep -Fq 'github.com/quic-go/quic-go v0.60.0' "$ROOT/go.mod" \
    || fail "quic-go direct dependency is not pinned"
grep -Fq 'github.com/dop251/goja v0.0.0-20260701091749-b07b74453ea9' "$ROOT/go.mod" \
    || fail "goja direct dependency is not pinned"
grep -Fq 'github.com/dlclark/regexp2/v2 v2.2.1' "$ROOT/go.mod" \
    || fail "regexp2 timeout dependency is not pinned"
grep -Fq 'github.com/andybalholm/brotli v1.2.2' "$ROOT/go.mod" \
    || fail "Brotli decoding dependency is not pinned"
grep -Fq 'maxModuleCaptureHosts = 512' "$SIDECAR_CONFIG" \
    && grep -Fq 'maxActionMatchHosts = 512' "$SIDECAR_CONFIG" \
    && grep -Fq 'maxCertificateHosts = 512' "$SIDECAR_CONFIG" \
    || fail "sidecar capture/action/certificate host bounds are not 512"
grep -Fq 'servePlainHTTPConnection' "$ROOT/proxy.go" \
    || fail "plain HTTP module interception is missing"
grep -Fq 'BodyMode' "$ROOT/module_runtime.go" \
    || fail "binary body script support is missing"
grep -Fq 'brotli.NewReader' "$ROOT/content_encoding.go" \
    || fail "bounded Brotli decoding is missing"
grep -Fq 'transform(context)' "$ROOT/module_runtime.go" \
    || fail "native transform entry point is missing"
grep -Fq 'compiledRule.hosts.Match' "$ROOT/module_runtime.go" \
    || fail "native actions do not use the per-snapshot capture-host matcher"
grep -Fq 'contextObject["network"]' "$ROOT/module_runtime.go" \
    || fail "declared origin permissions do not expose the bounded network capability"
grep -Fq 'dialSOCKS5TCP' "$ROOT/module_network.go" \
    || fail "extension network requests do not return through authenticated mihomo SOCKS5"
grep -Fq 'ExecutionOrder' "$ROOT/config.go" \
    || fail "sidecar config has no explicit extension execution order"
grep -Fq 'engineLogsSocketPath' "$SIDECAR_LOGS" \
    && grep -Fq '"/run/5gpn-intercept/logs.sock"' "$SIDECAR_LOGS" \
    && grep -Fq 'os.Chmod(path, 0o660)' "$SIDECAR_LOGS" \
    || fail "sidecar engine log UDS path or permissions are not fixed"
grep -Fq 'engineLogRingCapacity' "$SIDECAR_LOGS" \
    && grep -Fq '= 1000' "$SIDECAR_LOGS" \
    && grep -Fq 'maxEngineLogWebSockets' "$SIDECAR_LOGS" \
    && grep -Fq '= 8' "$SIDECAR_LOGS" \
    || fail "sidecar engine log memory or connection bounds are missing"
grep -Fq 'console.Set("warn", logger("warn"))' "$SIDECAR_RUNTIME" \
    && grep -Fq 'console.Set("error", logger("error"))' "$SIDECAR_RUNTIME" \
    || fail "native console levels are not mapped into structured engine logs"
grep -Fq 'script=%q' "$SIDECAR_RUNTIME" \
    && fail "native console text is still written to journald"
grep -Fq 'engine log service unavailable; continuing without UI log streaming' "$SIDECAR_MAIN" \
    && grep -Fq 'engine log service stopped unexpectedly; data plane remains active' "$SIDECAR_MAIN" \
    || fail "engine log IPC failures can still stop the interception data plane"
# The whole call is pinned, not just its prefix: the failure these two lines
# describe is allowed to name the host and the protocol, exactly as every other
# exit in the same handler does, but must never format the error value, which
# quotes script-controlled text. The cause goes to the engine log instead, where
# truncateEngineLogField bounds it.
grep -Fq 'log.Printf("intercept: request transformation failed host=%s protocol=%s", host, r.Proto)' "$SIDECAR_PROXY" \
    && grep -Fq 'log.Printf("intercept: response transformation failed host=%s protocol=%s", host, r.Proto)' "$SIDECAR_PROXY" \
    || fail "script transformation details can still reach journald"
grep -Fq 'log.Print("intercept: could not read replacement config; retaining the last valid snapshot")' "$SIDECAR_CONFIG" \
    && grep -Fq 'log.Print("intercept: ignoring invalid replacement config; retaining the last valid snapshot")' "$SIDECAR_CONFIG" \
    || fail "config rejection summaries are not journald-safe"
# Split from the gateway's copy, which scanned both trees. Each repository now
# asserts this about its own source; the name is assembled at runtime so this
# file does not itself contain the string it forbids.
retired_client="$(printf '%s%s' 'lo' 'on')"
grep -Rni "$retired_client" "$ROOT" \
    --exclude-dir=.git --exclude-dir=tests --exclude='*.md' 2>/dev/null | grep -q . \
    && fail "retired third-party plugin compatibility is still present"

if [[ "$rc" == 0 ]]; then
    echo "test_sidecar_policy: PASS"
else
    echo "test_sidecar_policy: FAIL"
fi
exit "$rc"
