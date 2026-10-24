# FaceUnlock

Unlock your Mac and your Linux machine with Face ID on your iPhone, from anywhere, on any network.

```
iPhone ──HTTPS──▶ relay (faceunlock.dinkelworks.nl, Cloudflare) ◀──WebSocket── Mac app / Linux agent
```

- **iPhone app** (`iOS/`): tap **Unlock**, or just open the app, or use Siri, Shortcuts or the Action button. Look at the phone and the computer unlocks.
- **Mac app** (`Mac/`): menu bar app. Types your login password into the lock screen when a paired iPhone asks.
- **Linux agent** (`linux/`): a single static binary run as a systemd user service.
  - On Omarchy it types your password into Omarchy's lock screen with `wtype`.
  - With hyprlock it unlocks with `SIGUSR1`.
  - On GNOME and KDE it uses `loginctl unlock-session`.
- **Relay** (`relay/`): Cloudflare Worker with one Durable Object per computer. Computers connect *out* to it, so nothing on your machines listens for connections, and neither device needs to be on the same network.
- **Core** (`Core/`): the shared Swift protocol and security checks, plus `fake-phone`, a terminal stand-in for the iPhone.

## How it stays safe

- **Phone key:** pairing creates a P-256 key in the iPhone's Secure Enclave. It can only sign after Face ID: there's no passcode fallback, and enrolling a new face invalidates it.
- **Every command is a challenge and response:**
  - The computer hands out a single-use nonce, valid for 60 s.
  - It only accepts a signature over that nonce, the computer's ID, the iPhone's ID and the action.
- **The relay is not trusted.** It only passes messages along. It can't forge or replay commands, and it never sees the pairing code: the iPhone sends an HMAC proof tied to its key instead.
- **Relay slot:** each computer claims its slot on the relay with a secret, so nobody else can connect in its place.
- **Login passwords stay on each computer:**
  - Mac: in the login keychain. Linux: in the GNOME keyring.
  - Each is checked against your account before it's typed (OpenDirectory on the Mac, `unix_chkpwd` on Linux).
  - Typing stops if the screen unlocks partway through, so the password can't end up in an app.

## Setup

### Mac
1. Accept the Xcode license once: `sudo xcodebuild -license accept`
2. Run `scripts/build-mac.sh`. Then, in the FaceUnlock menu bar item:
   - Grant **Accessibility** access.
   - **Save** your login password.

### iPhone
1. Connect it with a cable and enable Developer Mode.
2. Run `scripts/install-iphone.sh`.
3. Trust the developer in Settings › General › VPN & Device Management.

With a free Apple developer account the app stops opening after 7 days. Re-run the script to renew it.

### Linux (Omarchy)
```sh
scripts/build-linux.sh                                   # on the Mac
scp build/linux/faceunlock-agent-amd64 omarchy:~/.local/bin/faceunlock-agent

# on the Linux machine:
faceunlock-agent install-service   # systemd user service, starts with your session
faceunlock-agent set-password      # needed for Omarchy's lock screen; verified, stored in the keyring
faceunlock-agent pair              # shows the QR code to scan with the iPhone Camera
faceunlock-agent status
```
Logs: `journalctl --user -u faceunlock-agent -f`

### Pairing
On the Mac click **Pair iPhone…**; on Linux run `faceunlock-agent pair`. Then scan the QR code with the iPhone Camera app.

## Limitations

- **The computer has to be awake and logged in.**
  - After a restart, type your password once yourself.
  - A sleeping computer can't be reached. On the Mac, "Keep Mac awake on power adapter" (on by default) prevents idle sleep while it's charging.
- **Linux on Omarchy needs `wtype`, `secret-tool` and an unlocked GNOME keyring.** Omarchy ships all three.

## Development

```sh
cd Core && swift test                    # protocol and security tests (incl. vectors shared with Go)
cd linux && go test ./...                # agent tests
cd relay && npm test                    # relay forwarding tests (local Cloudflare runtime)
cd relay && npx wrangler dev             # local relay on :8787; npx wrangler deploy to publish

# End to end without a phone: off Linux the agent uses a pretend lock screen.
(cd linux && go build -o /tmp/faceunlock-agent .)
FACEUNLOCK_CONFIG_DIR=/tmp/fu /tmp/faceunlock-agent run &
FACEUNLOCK_CONFIG_DIR=/tmp/fu /tmp/faceunlock-agent pair     # prints faceunlock://pair?d=…
swift run --package-path Core fake-phone pair 'faceunlock://pair?d=…'
swift run --package-path Core fake-phone lock|unlock|status|test-replay|test-bad-signature
```

`project.yml` is the source of truth for the Xcode project (`xcodegen generate`). The Mac app's relay can be overridden with `defaults write nl.dinkelworks.faceunlock.mac relayURL http://localhost:8787`.
