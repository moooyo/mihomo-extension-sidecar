# Live verification of the control API

`control-api-live.sh` drives the built sidecar binary through its control API
with `curl`, from outside Go entirely.

That independence is the point. The coordinator's Go client and the sidecar's Go
handlers were written together and will agree with each other about the wire
format whether or not that format is what either one documents. A shell client
that only knows the published paths and JSON shapes cannot share a
misunderstanding with either side.

It covers: socket mode, capability discovery, that staging does not make a
bundle live, compare-and-swap refusal, commit, the per-plugin view the console
renders, an idempotent repeat of a landed commit, abort refusing the live
bundle, generation advance on supersede, rejection of an invalid document,
reload of the served bundle across a restart, and that a purge leaves nothing a
later start resurrects.

## Running

Needs a Linux host with the sidecar built, and a real
`/etc/5gpn/intercept/config.json` to derive a fixture from. The document
validator pins the data-plane listen address, so the script stops the production
`5gpn-intercept` for the duration and starts it again at the end.

```sh
go build -o /tmp/5gpn-intercept .
scp /tmp/5gpn-intercept target:/tmp/
scp test/control-api-live.sh target:/tmp/
ssh target 'bash /tmp/sidecar-api-test.sh'
```
