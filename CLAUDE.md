# FaceUnlock

Unlock Ruben's Mac and Linux (Omarchy) machine with Face ID on his iPhone, from anywhere. See README.md for setup and the security model.

## Layout

- `Core/`: Swift package shared by the iOS and Mac apps. `Protocol.swift` (wire format), `Authenticator.swift` (pairing, single-use nonces, signature checks), `RelayClient.swift` (phone side), `FakePhone/` (CLI stand-in for the iPhone).
- `Mac/`: menu bar app. `RelayConnection.swift` keeps the outgoing WebSocket; `ScreenController.swift` types the password into the lock screen; `PasswordStore.swift` keychain + OpenDirectory check; `ControlSocket.swift` the Unix socket the sudo checker talks to (approvals live in `AppModel.swift`); `PasswordDialog.swift` finds and fills system password dialogs (coreautha "… is trying to unlock", SecurityAgent admin dialogs) through Accessibility. `Mac/PAM/`: `pam_faceunlock.c` (macOS has no pam_exec, so this runs the checker for sudo) and `pam_check.c` (tests PAM with it); built by `scripts/enable-mac-sudo.sh`, excluded from the app target.
- `iOS/`: iPhone app. `DeviceKey.swift` (Secure Enclave key, Face ID only), `PhoneModel.swift` (pair/unlock/lock, smart open, approvals, unlock all, live refresh while open, ntfy topic), `Intents.swift` (Shortcuts/Action button).
- `linux/`: Go agent (`faceunlock-agent`), static binary, systemd user service. Lock screen backends in `screen_linux.go`: Omarchy's Quickshell lock (types with `wtype`; no unlock IPC exists), hyprlock (`SIGUSR1`), logind (GNOME/KDE). Off Linux it uses a fake screen for testing. Approvals: `approvals.go` (agent side, ntfy), `checker.go` (`faceunlock-agent pam`, the root-owned checker PAM runs on Linux *and* on the Mac), `sudo_setup.go` (`enable-sudo`/`disable-sudo`), `procinfo_*.go`.
- `relay/`: Cloudflare Worker + Durable Object per machine at https://faceunlock.dinkelworks.nl (DinkelWorks account). Only routes; not trusted.
- `project.yml`: source of truth for the Xcode project (`xcodegen generate`; the .xcodeproj and Info.plists are generated and not committed).

## Keep in sync

`Core/Sources/FaceUnlockCore/Protocol.swift` and `linux/protocol.go` implement the same protocol (field names, signed message bytes incl. `ApprovalMessage`, pairing HMAC, error messages in `Authenticator.swift` ↔ `linux/auth.go`). The cross-language test vectors in both test suites must keep passing. The control-socket messages (`approvers`, `approval`, checker lines) in `Mac/ControlSocket.swift` match `linux/control.go` and `linux/approvals.go`, because the same Go checker talks to the Mac app.

Approval trust model: for sudo/polkit the checker (root) creates the nonce and verifies the signature against root-owned `approvers.json`; the agent, Mac app and relay only carry messages. Keep it that way: nothing user-level may decide a sudo approval. Mac password dialogs are the exception by design: the Mac app verifies those itself (same trust as unlock, since it holds the password anyway), types only into Apple-signed coreautha/SecurityAgent (code-signature check) and only via `postToPid`. The iPhone never approves without a tap on Approve.

## Commands

- All tests: `scripts/test.sh`
- Mac app: `scripts/build-mac.sh` (builds, installs to ~/Applications, restarts it)
- iPhone: `scripts/install-iphone.sh` (cable or paired device; free Apple team U78YQGE72M, so installs expire after 7 days)
- Linux binaries: `scripts/build-linux.sh` → `build/linux/`
- Relay: `cd relay && npx wrangler deploy`. A deploy briefly drops every agent connection; they reconnect within seconds.
- End to end without devices: run the Go agent on the Mac (fake screen) and pair `fake-phone` with it; see README "Development" (also covers approvals and the Mac PAM module via `pam-check --direct`, no root needed).
- sudo approvals: Linux `sudo faceunlock-agent enable-sudo`; Mac `scripts/enable-mac-sudo.sh` (Ruben runs it; it needs his password and edits `/etc/pam.d/sudo_local`).

## Gotchas

- The Mac app must stay signed with the Apple Development certificate: Keychain access and the Accessibility grant are tied to that signature and would be lost with ad-hoc signing.
- Simulator builds need signing for the keychain: `CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES`.
- In tests, never lock or unlock the real Mac screen unless Ruben asks; use the Go agent's fake screen. Don't change `/etc/pam.d` on the real Mac in tests; real Linux PAM can be tested in a Docker container.
- A harmless password dialog for testing: a tiny Swift tool calling `LAContext().evaluatePolicy(.deviceOwnerAuthentication, …)` (coreautha) or `osascript -e 'do shell script "true" with administrator privileges'` (SecurityAgent). The Mac app asks the real iPhone about it, so tell Ruben first. These SwiftUI dialogs expose button labels as AX descriptions and report the secure field's contents via AXValue (never log it).
- macOS has no `pam_exec`; a PAM module that fails to load breaks sudo entirely, which is why `enable-sudo` tests it through a temporary `/etc/pam.d/faceunlock-check` first.

## Status and next steps (2026-10-25)

Working: real iPhone → relay → Mac unlock. Linux agent built and tested with the fake screen only; Ruben tests on Omarchy himself.

Built 2026-10-24/25 (uncommitted until Ruben asks): smart open (hello reports `locked` and waiting `approvals`; one locked computer → unlock, several → list + "Unlock all"; approvals always need a tap), sudo/polkit approvals (Linux `pam_exec`, Mac `pam_faceunlock` via `/etc/pam.d/sudo_local`, root-owned Go checker), ntfy notifications (iPhone picks a topic, sends it in hello), Mac password dialogs (1Password's "trying to unlock", admin dialogs). Mac sudo is enabled and approved from the real iPhone; a password dialog was filled after a real iPhone approval.

Not done: Omarchy sudo setup (Ruben). Real APNs needs a paid Apple account.
