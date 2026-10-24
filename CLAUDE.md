# FaceUnlock

Unlock Ruben's Mac and Linux (Omarchy) machine with Face ID on his iPhone, from anywhere. See README.md for setup and the security model.

## Layout

- `Core/`: Swift package shared by the iOS and Mac apps. `Protocol.swift` (wire format), `Authenticator.swift` (pairing, single-use nonces, signature checks), `RelayClient.swift` (phone side), `FakePhone/` (CLI stand-in for the iPhone).
- `Mac/`: menu bar app. `RelayConnection.swift` keeps the outgoing WebSocket; `ScreenController.swift` types the password into the lock screen; `PasswordStore.swift` keychain + OpenDirectory check.
- `iOS/`: iPhone app. `DeviceKey.swift` (Secure Enclave key, Face ID only), `PhoneModel.swift` (pair/unlock/lock flows), `Intents.swift` (Shortcuts/Action button).
- `linux/`: Go agent (`faceunlock-agent`), static binary, systemd user service. Lock screen backends in `screen_linux.go`: Omarchy's Quickshell lock (types with `wtype`; no unlock IPC exists), hyprlock (`SIGUSR1`), logind (GNOME/KDE). Off Linux it uses a fake screen for testing.
- `relay/`: Cloudflare Worker + Durable Object per machine at https://faceunlock.dinkelworks.nl (DinkelWorks account). Only routes; not trusted.
- `project.yml`: source of truth for the Xcode project (`xcodegen generate`; the .xcodeproj and Info.plists are generated and not committed).

## Keep in sync

`Core/Sources/FaceUnlockCore/Protocol.swift` and `linux/protocol.go` implement the same protocol (field names, signed message bytes, pairing HMAC, error messages in `Authenticator.swift` ↔ `linux/auth.go`). The cross-language test vectors in both test suites must keep passing.

## Commands

- All tests: `scripts/test.sh`
- Mac app: `scripts/build-mac.sh` (builds, installs to ~/Applications, restarts it)
- iPhone: `scripts/install-iphone.sh` (cable or paired device; free Apple team U78YQGE72M, so installs expire after 7 days)
- Linux binaries: `scripts/build-linux.sh` → `build/linux/`
- Relay: `cd relay && npx wrangler deploy`. A deploy briefly drops every agent connection; they reconnect within seconds.
- End to end without devices: run the Go agent on the Mac (fake screen) and pair `fake-phone` with it; see README "Development".

## Gotchas

- The Mac app must stay signed with the Apple Development certificate: Keychain access and the Accessibility grant are tied to that signature and would be lost with ad-hoc signing.
- Simulator builds need signing for the keychain: `CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES`.
- In tests, never lock or unlock the real Mac screen unless Ruben asks; use the Go agent's fake screen.

## Status and next steps (2026-10-24)

Working: real iPhone → relay → Mac unlock. Linux agent built and tested with the fake screen only; Ruben tests on Omarchy himself.

Planned, in Ruben's preferred direction:
1. "Smart open": on app open, ask every paired computer for its lock state first (no Face ID); nothing locked → no prompt; one locked → unlock it; several → offer each plus "Unlock both" with one Face ID.
2. Phone approvals for other password prompts: `sudo` and polkit admin prompts on Linux via `pam_exec`, then the Mac (`/etc/pam.d/sudo_local` PAM module, SecurityAgent dialogs).
3. Notifications so the computer can ask the phone (free ntfy app; real APNs needs a paid Apple account).
