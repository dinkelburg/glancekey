# FaceUnlock test report — 2026-10-24

Production relay: https://faceunlock.dinkelworks.nl. All desktop commands used the Go agent's fake in-memory screen on macOS, with isolated temporary state. No real screen or Mac app was used.

| Test | Result and evidence |
| --- | --- |
| Xcode prerequisite | **Skipped:** `xcrun --sdk iphoneos --show-sdk-path` exited 69: Xcode license not accepted. No license acceptance, sudo, Xcode generation, or app builds attempted. |
| Swift build and Core tests | **PASS:** Command Line Tools build succeeded; all 14 tests in 2 suites passed, including signature/HMAC vectors, pairing expiry, nonce expiry/replay, and wrong-key/action rejection. |
| Go tests and Linux vet | **PASS:** 7 tests passed in an uncached run; `GOOS=linux go vet ./...` and `go test -race -count=1 ./...` passed. |
| Linux cross-build | **PASS:** `scripts/build-linux.sh` produced static ELF x86-64 and ARM64 binaries; confirmed with `file`. |
| Relay typecheck | **PASS:** `npx tsc --noEmit`, both before and after the fix. |
| Production pairing and persistence | **PASS:** background `faceunlock-agent pair` supplied the URL to `fake-phone pair`; agent CLI reported connected, fake screen, and paired `fake-phone`. `agent.json` contained exactly one device matching the phone ID and had mode 0600. |
| Production status/lock/unlock/status | **PASS:** observed `locked=false → true → false`, with `ok=true` throughout. |
| Replay and bad signature | **PASS:** both fake-phone test commands explicitly reported rejection with HTTP 403. Replay: “The request was out of date. Try again.” Forgery: “The computer rejected this iPhone's signature.” |
| Offline agent | **PASS:** stopped agent; fake-phone exited 1 with “Your computer isn't connected to FaceUnlock right now…”; curl confirmed HTTP 503. |
| Restart recovery | **PASS:** restarted with the same state; connected in approximately 0.243 s and fake-phone status succeeded. |
| Wrong relay secret | **PASS:** copied state and changed only `agentSecret`; second agent logged HTTP 403, “This machine id belongs to another agent.” Original agent continued serving status successfully. |
| Invalid machine path / method | **PASS:** malformed machine ID returned HTTP 400, “Invalid machine id.” Unknown well-formed ID returned HTTP 503. GET on a phone endpoint returned HTTP 405, “Use POST.” |
| Cancelled pairing code | **PASS:** interrupted the pairing CLI, then reused its URL; fake-phone exited 1 with “Pairing isn't active. Start pairing on your computer first.” Actual five-minute expiry was covered by Swift unit tests, not a wall-clock production wait. |
| Pause/resume | **PASS:** SIGSTOP for 60 s, then SIGCONT; agent logged “Woke from sleep; reconnecting” and a fresh connection in approximately 1.231 s; subsequent phone status succeeded. |
| Concurrent unlocks | **PASS:** two simultaneous fake-phone processes returned successful “Unlocked” and “Already unlocked”; subsequent status was unlocked. |
| Unpair | **PASS:** `faceunlock-agent unpair fake-phone` succeeded; fake-phone then exited 1 with “This iPhone isn't paired with that computer anymore. Pair it again.” Curl independently confirmed HTTP 403 while the agent remained connected; CLI reported no paired phones. |
| Disconnect during pending request | **FAIL in production; fixed locally:** paused the agent, sent an HTTP hello request, then killed the agent after 1 s. Production returned HTTP 504 only after 25.079 s. Local regression tests failed before the fix and passed afterward. **Requires relay redeployment.** |
| Local relay regression suite | **PASS:** 3 tests using Miniflare/workerd: normal forwarding preserves status/body; socket close promptly returns 503; replacement fails old pending requests and successfully routes new ones. Post-fix close/replacement tests took about 10–11 ms each in the initial successful run. |
| Cleanup | **PASS:** all test agents, pairing CLI processes, and local workerd processes stopped; temporary agent/phone state and logs deleted. No wrangler process or deployment was started. |

## Latency

Five locked-to-unlocked fake-phone runs against production: **339, 217, 218, 225, 254 ms**. Median **225 ms**, range **217–339 ms**. The initial unlock was **187 ms**.

These are whole CLI elapsed times, including process startup, challenge request, signing, command request, and the fake screen action. They do not measure Face ID or physical desktop password typing. Restart connection: **243 ms**. Reconnection after SIGCONT: **1.231 s**.

## Bugs and source review

1. **Confirmed relay bug, fixed locally:** `relay/src/index.ts:131` previously closed sockets without resolving their pending HTTP requests. The same omission affected replacement connections (`relay/src/index.ts:71`). Requests waited for the 25-second timer; the phone's 10-second hello timeout could instead surface a generic reachability error. Pending requests now retain their socket and receive HTTP 503 on close, error, or replacement. The existing timeout remains for agents that stay connected without answering. No deployment was performed.
2. **Unverified desktop race, unchanged:** `linux/screen_linux.go:205` checks lock state, then invokes a separate `wtype` process at line 208. Manual unlock between those operations can let the next character reach the unlocked desktop. The comment at line 186 overstates the guarantee. No real Linux session was available to reproduce the race; a robust fix requires coordinating input with the lock screen, beyond this small relay fix.

Swift/Go protocol version, field names, HMAC input, signed-command bytes, key/signature encoding, and lifetimes match for normal app traffic, supported by cross-language vectors and production interoperability. Go heartbeat/reconnect behavior passed the pause test. Mac relay reconnect code received static review only; no further confirmed fault was found.

Omarchy Escape clearing agrees with the [upstream LockView key handler](https://github.com/omacom/omarchy/blob/quattro/shell/plugins/lock/LockView.qml#L195-L204). This does not verify the installed Linux version, Wayland focus, keyring, PAM, DPMS, or real password typing.

## Files changed

- `relay/src/index.ts`: resolve socket-associated pending requests on close, error, and replacement.
- `relay/tests/relay.test.mjs` (new): three local Cloudflare-runtime regression tests, with bounded timeouts; uses the already-installed Miniflare and TypeScript packages, without installing dependencies.
- `TEST-REPORT.md` (new): this sanitized report.
- Generated/rebuilt artifacts: `Core/.build/` and `build/linux/faceunlock-agent-{amd64,arm64}`. No other source or configuration files were changed.

## Reproduce local validation

```sh
cd relay
npx tsc --noEmit
node --test tests/relay.test.mjs
```

Python urllib requests were rejected at Cloudflare with error 1010, before reaching the Worker. Raw HTTP cases were rerun with curl and produced the application responses above; this was a test-client issue, not a FaceUnlock failure.

Not tested: Mac/iOS app builds, real Face ID/Secure Enclave, real Mac unlocking, a physical Linux/Omarchy session, actual machine suspend/network loss, or the patch on the deployed relay. SIGSTOP exercises process suspension and recovery, not an entire sleeping machine.
