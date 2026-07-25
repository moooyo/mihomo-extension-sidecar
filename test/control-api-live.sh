#!/bin/bash
set -u
D=/tmp/sidecar-test
BIN=/tmp/5gpn-intercept
SOCK=$D/control.sock
CTL="curl -s --unix-socket $SOCK"
pass=0; fail=0
chk(){ if echo "$3"|grep -qE "$2"; then echo "  PASS  $1"; pass=$((pass+1));
       else echo "  FAIL  $1"; echo "        want ~ $2"; echo "        got    $(echo "$3"|head -c 300)"; fail=$((fail+1)); fi; }
notin(){ if echo "$3"|grep -q "$2"; then echo "  FAIL  $1"; fail=$((fail+1)); else echo "  PASS  $1"; pass=$((pass+1)); fi; }

# The document validator pins the data-plane listen address, so the production
# sidecar has to stand down for the duration. test-env is disposable and it is
# restarted at the end.
systemctl stop 5gpn-intercept 2>/dev/null || true
rm -rf $D; mkdir -p $D/store
# One real extension, real shape, synthetic credentials.
python3 - <<'PY'
import json
real=json.load(open('/etc/5gpn/intercept/config.json'))
wloc=next(m for m in real['modules'] if m['id']=='io.5gpn.apple-wloc')
doc={'version':real['version'],'listen':real['listen'],
     'username':'module-in-0000000000000000000000','password':'module-in-password-0000000000000000',
     'tls_cert':real['tls_cert'],'tls_key':real['tls_key'],
     'upstream_proxy':{'address':real['upstream_proxy']['address'],
                       'username':'module-up-0000000000000000000000',
                       'password':'module-up-password-0000000000000000'},
     'mitm':real['mitm'],'execution_order':[wloc['id']],'modules':[wloc]}
json.dump(doc,open('/tmp/sidecar-test/bundle.json','w'),indent=2)
doc2=json.loads(json.dumps(doc)); doc2['modules'][0]['enabled']=False
json.dump(doc2,open('/tmp/sidecar-test/bundle2.json','w'),indent=2)
print('fixtures written')
PY

nohup $BIN --config $D/bundle.json --bundle-store $D/store --control-socket $SOCK > $D/sidecar.log 2>&1 &
for i in $(seq 1 60); do [ -S $SOCK ] && break; sleep 0.2; done
[ -S $SOCK ] || { echo "sidecar never bound the control socket"; tail -5 $D/sidecar.log; exit 1; }

echo "== 1. socket permissions =="
mode=$(stat -c '%a' $SOCK)
chk "control socket is 0600, not world-reachable" '^600$' "$mode"
dirmode=$(stat -c '%a' $D)
echo "  (containing dir mode: $dirmode)"

echo "== 2. capability discovery =="
out=$($CTL http://x/capabilities)
chk "schema advertised"   '"schema":1'        "$out"
chk "process instance"    '"instanceId":"[0-9a-f]' "$out"
chk "bundles feature"     '"bundles":1'       "$out"
chk "plugins feature"     '"plugins":1'       "$out"
chk "responses are no-store" 'no-store' "$($CTL -D - -o /dev/null http://x/capabilities)"

echo "== 3. fresh sidecar has no pushed bundle =="
out=$($CTL http://x/state)
chk "no active bundle" '"activeBundle":""' "$out"

echo "== 4. stage does not make it live =="
out=$($CTL -X PUT -H 'Content-Type: application/json' --data-binary @$D/bundle.json http://x/bundles/b1)
chk "staged with a digest" '"digest":"[0-9a-f]{64}"' "$out"
out=$($CTL http://x/state)
chk "still not live"       '"activeBundle":""'       "$out"
chk "listed as staged"     '"stagedBundles":\["b1"\]' "$out"

echo "== 5. commit refuses a wrong expected-active =="
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveBundle":"nope"}' http://x/bundles/b1/commit)
chk "cas_conflict" '"code":"cas_conflict"' "$out"

echo "== 6. commit =="
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveBundle":""}' http://x/bundles/b1/commit)
chk "committed as generation 1" '"generation":1' "$out"
out=$($CTL http://x/state)
chk "active"          '"activeBundle":"b1"' "$out"
chk "master enabled"  '"masterEnabled":true' "$out"
chk "one extension"   '"extensions":1'       "$out"
chk "capture hosts"   '"captureHosts":2'     "$out"

echo "== 7. the per-plugin view the console renders =="
out=$($CTL http://x/plugins)
chk "names the extension"  'io.5gpn.apple-wloc'  "$out"
chk "carries its name"     'Apple WLOC'          "$out"
chk "carries its version"  '"version":"1.1.1"'   "$out"
chk "carries capture hosts" 'gs-loc.apple.com'   "$out"
chk "carries action count" '"actions":1'         "$out"

echo "== 8. an idempotent repeat of a landed commit =="
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveBundle":""}' http://x/bundles/b1/commit)
chk "same success, not a conflict" '"bundleId":"b1"' "$out"
notin "did not report a conflict" 'cas_conflict' "$out"

echo "== 9. abort refuses the live bundle =="
out=$($CTL -X POST http://x/bundles/b1/abort)
chk "wrong_state" '"code":"wrong_state"' "$out"

echo "== 10. superseding advances the generation =="
$CTL -X PUT -H 'Content-Type: application/json' --data-binary @$D/bundle2.json http://x/bundles/b2 > /dev/null
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveBundle":"b1"}' http://x/bundles/b2/commit)
chk "generation 2" '"generation":2' "$out"
out=$($CTL http://x/state)
chk "b2 is live"      '"activeBundle":"b2"' "$out"
chk "b1 is retained"  '"b1"'                "$out"

echo "== 11. an invalid document is refused =="
out=$($CTL -X PUT -H 'Content-Type: application/json' -d '{"version":5,"modules":"not an array"}' http://x/bundles/bad)
chk "refused" '"code":' "$out"

echo "== 12. the sidecar owns its state across a restart =="
pkill -x 5gpn-intercept; sleep 1
nohup $BIN --config $D/bundle.json --bundle-store $D/store --control-socket $SOCK > $D/sidecar2.log 2>&1 &
for i in $(seq 1 60); do [ -S $SOCK ] && break; sleep 0.2; done
out=$($CTL http://x/state)
chk "reloaded the bundle it was serving" '"activeBundle":"b2"' "$out"
chk "recovery logged" 'serving pushed bundle b2' "$(cat $D/sidecar2.log)"
first=$(echo "$out" | grep -o '"instanceId":"[^"]*"')
echo "  (new process instance: $first)"

echo "== 13. purge leaves nothing to resurrect =="
$CTL -X DELETE http://x/bundles > /dev/null
out=$($CTL http://x/state)
chk "purged" '"activeBundle":""' "$out"
pkill -x 5gpn-intercept; sleep 1
nohup $BIN --config $D/bundle.json --bundle-store $D/store --control-socket $SOCK > $D/sidecar3.log 2>&1 &
for i in $(seq 1 60); do [ -S $SOCK ] && break; sleep 0.2; done
out=$($CTL http://x/state)
chk "still purged after restart" '"activeBundle":""' "$out"
notin "nothing resurrected" 'recovered bundle' "$(cat $D/sidecar3.log)"

pkill -x 5gpn-intercept
systemctl start 5gpn-intercept 2>/dev/null || true
echo
echo "passed=$pass failed=$fail"
