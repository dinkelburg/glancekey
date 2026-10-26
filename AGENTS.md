# GlanceKey

Unlock Ruben's Mac and Linux (Omarchy) machine with Face ID on his iPhone, from anywhere. See README.md for setup and the security model.

## Layout

- `Core/`: Swift package shared by the iOS and Mac apps. `Protocol.swift` (wire format), `Authenticator.swift` (pairing, single-use nonces, signature checks), `RelayClient.swift` (phone side), `FakePhone/` (CLI stand-in for the iPhone).
- `Mac/`: menu bar app. `RelayConnection.swift` keeps the outgoing WebSocket; `ScreenController.swift` types the password into the lock screen; `PasswordStore.swift` keychain + OpenDirectory check; `ControlSocket.swift` the Unix socket the sudo checker talks to (approvals live in `AppModel.swift`); `PasswordDialog.swift` finds and fills system password dialogs (coreautha "… is trying to unlock", SecurityAgent admin dialogs) through Accessibility. `Mac/PAM/`: `pam_module.c` (macOS has no pam_exec, so this runs the checker for sudo) and `pam_check.c` (tests PAM with it); built by `scripts/enable-mac-sudo.sh`, excluded from the app target.
- `iOS/`: iPhone app. `DeviceKey.swift` (Secure Enclave key, Face ID only), `PhoneModel.swift` (pair/unlock/lock, smart open, approvals, unlock all, live refresh while open, notifications), `PhoneApp.swift` (`AppDelegate`: push token, notification taps), `Intents.swift` (Shortcuts/Action button).
- `linux/`: Go agent (`glancekey-agent`), static binary, systemd user service. Lock screen backends in `screen_linux.go`: Omarchy's Quickshell lock (types with `wtype`; no unlock IPC exists), hyprlock (`SIGUSR1`), logind (GNOME/KDE). Off Linux it uses a fake screen for testing. Approvals: `approvals.go` (agent side, notifications), `checker.go` (`glancekey-agent pam`, the root-owned checker PAM runs on Linux *and* on the Mac), `sudo_setup.go` (`enable-sudo`/`disable-sudo`), `procinfo_*.go`.
- `relay/`: Cloudflare Worker + Durable Object per machine at https://relay.glancekey.com (DinkelWorks account). The old https://glancekey.dinkelworks.nl stays on the same Worker for installs and pairings that still use it. Only routes; not trusted. It also sends the APNs notifications computers ask for over their WebSocket (`notify`), with the APNs key in the Worker secret `APNS_KEY` (README "Notifications").
- `site/`: the landing page and privacy policy at https://www.glancekey.com (static files in `site/public`, served as a Cloudflare Worker with static assets, DinkelWorks account). `site/redirect` is a separate tiny Worker that sends glancekey.com and the old glancekey.dinkel.works there. No JavaScript, cookies, third-party requests or request logs; the CSP in `public/_headers` enforces the first three. Its claims (open source, self-hostable, no data collected, the security model, what the relay sees and stores) must stay true to the code: update the page when those change.
- `project.yml`: source of truth for the Xcode project (`xcodegen generate`; the .xcodeproj and Info.plists are generated and not committed).

## Keep in sync

`Core/Sources/AppCore/Protocol.swift` and `linux/protocol.go` implement the same protocol (field names, signed message bytes incl. `ApprovalMessage`, pairing HMAC, error messages in `Authenticator.swift` ↔ `linux/auth.go`, and `RelayNotification`, which `relay/src/index.ts` reads). The cross-language test vectors in both test suites must keep passing. The control-socket messages (`approvers`, `approval`, checker lines) in `Mac/ControlSocket.swift` match `linux/control.go` and `linux/approvals.go`, because the same Go checker talks to the Mac app.

The app's name is defined only in `Core/Sources/AppCore/Brand.swift`, `linux/brand.go`, `project.yml` (`APP_NAME`/`APP_ID`; the scripts read them through `scripts/brand.sh`), `relay/src/index.ts` (`APP_NAME`) and `relay/wrangler.jsonc`. Code uses those constants and never spells the name out; `scripts/check-brand.sh` (part of `scripts/test.sh`) fails otherwise. Docs (`*.md`) and the website (`site/`) spell it out, so update them by hand after a rename. Changing the display name is cheap. Changing the id changes bundle IDs, keychain items, the URL scheme and the paths on the computers, so everything has to be paired and set up again. The `faceunlock…/v1` prefixes in signed messages and the pairing proof are fixed protocol constants from the app's first name (FaceUnlock), not branding: leave them.

Approval trust model: for sudo/polkit the checker (root) creates the nonce and verifies the signature against root-owned `approvers.json`; the agent, Mac app and relay only carry messages. Keep it that way: nothing user-level may decide a sudo approval. Mac password dialogs are the exception by design: the Mac app verifies those itself (same trust as unlock, since it holds the password anyway), types only into Apple-signed coreautha/SecurityAgent (code-signature check) and only via `postToPid`. The iPhone never approves without a tap on Approve.

## Commands

- All tests: `scripts/test.sh`
- Mac app: `scripts/build-mac.sh` (builds, installs to ~/Applications, restarts it)
- iPhone: `scripts/install-iphone.sh` (cable or paired device; Ruben's paid Developer Program team U78YQGE72M, so an install keeps opening for a year)
- Linux binaries: `scripts/build-linux.sh` → `build/linux/`
- Relay: `cd relay && npx wrangler deploy`. A deploy briefly drops every agent connection; they reconnect within seconds.
- Website: `cd site && npm install && npx wrangler dev` (http://localhost:8788) to preview, `npm run deploy` to publish the site and its redirects.
- End to end without devices: run the Go agent on the Mac (fake screen) and pair `fake-phone` with it; see README "Development" (also covers approvals and the Mac PAM module via `pam-check --direct`, no root needed).
- sudo approvals: Linux `sudo glancekey-agent enable-sudo`; Mac `scripts/enable-mac-sudo.sh` (Ruben runs it; it needs his password and edits `/etc/pam.d/sudo_local`).

## Gotchas

- The Mac app must stay signed with the Apple Development certificate: Keychain access and the Accessibility grant are tied to that signature and would be lost with ad-hoc signing.
- Simulator builds need signing for the keychain: `CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES`.
- In tests, never lock or unlock the real Mac screen unless Ruben asks; use the Go agent's fake screen. Don't change `/etc/pam.d` on the real Mac in tests; real Linux PAM can be tested in a Docker container.
- A harmless password dialog for testing: a tiny Swift tool calling `LAContext().evaluatePolicy(.deviceOwnerAuthentication, …)` (coreautha) or `osascript -e 'do shell script "true" with administrator privileges'` (SecurityAgent). The Mac app asks the real iPhone about it, so tell Ruben first. These SwiftUI dialogs expose button labels as AX descriptions and report the secure field's contents via AXValue (never log it).
- macOS has no `pam_exec`; a PAM module that fails to load breaks sudo entirely, which is why `enable-sudo` tests it through a temporary `/etc/pam.d/glancekey-check` first.

## Status (2026-10-26)

- Renamed from FaceUnlock to GlanceKey on 2026-10-25, id included. The same day Ruben's iPhone and Mac moved to GlanceKey and FaceUnlock was removed from both, Mac sudo included (it now runs the GlanceKey checker), and the old `faceunlock-relay` worker was deleted. Omarchy still has the old agent.
- Tested on the real devices: iPhone → relay → Mac unlock, Mac sudo approval, a Mac password dialog. The Linux agent is tested with the fake screen only; Ruben tests on Omarchy himself.
- Not done: Omarchy sudo setup (Ruben).
- 2026-10-26: notifications moved from ntfy to Apple push and were rolled out. Ruben's Personal Team became his paid individual team with the same ID (U78YQGE72M). So the iPhone app updated in place and kept its pairings, and the Mac app kept its signature, Accessibility permission and keychain access. The relay runs with the APNs key "GlanceKey push" (key ID 55K782WVH5, Sandbox & Production) in the secret `APNS_KEY`, and the site is deployed. Tested the same day: a Mac `sudo` reached Ruben's locked iPhone as a notification. The Linux agent with push isn't on Omarchy yet.
