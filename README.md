# GlanceKey

Unlock your Mac and your Linux machine with Face ID on your iPhone, from anywhere, on any network.

```
iPhone ──HTTPS──▶ relay (glancekey.dinkelworks.nl, Cloudflare) ◀──WebSocket── Mac app / Linux agent
```

- **iPhone app** (`iOS/`): tap **Unlock**, or just open the app, or use Siri, Shortcuts or the Action button. Look at the phone and the computer unlocks.
  - Opening the app first asks every paired computer whether it's locked or waiting for an approval (no Face ID). One locked computer: it unlocks it. Several: it lists them, with **Unlock all** for one Face ID. While the app is open it keeps checking, so new requests show up within seconds.
  - It also approves `sudo` (and polkit dialogs on Linux) on your computers, and the Mac's password dialogs; see [Approve sudo with your iPhone](#approve-sudo-with-your-iphone) and [Mac password dialogs](#mac-password-dialogs). Approving always takes a tap on **Approve**, then Face ID.
- **Mac app** (`Mac/`): menu bar app. Types your login password into the lock screen, or into a password dialog, when a paired iPhone asks.
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
- **Approvals are checked as root:** for `sudo`, a root-owned checker verifies the iPhone's signature itself, against a root-owned list of iPhones. The app or agent in between only passes messages, so neither it nor anything running as you can approve. The iPhone signs exactly the command it showed you.
- **Password dialogs are filled like the lock screen:** the Mac app checks the iPhone's signature as for an unlock. It only types into Apple-signed dialog processes (checked by code signature), and the keystrokes go to that process alone, never to the app in front.

## Setup

### Mac
1. Accept the Xcode license once: `sudo xcodebuild -license accept`
2. Run `scripts/build-mac.sh`. Then, in the GlanceKey menu bar item:
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
scp build/linux/glancekey-agent-amd64 omarchy:~/.local/bin/glancekey-agent

# on the Linux machine:
glancekey-agent install-service   # systemd user service, starts with your session
glancekey-agent set-password      # needed for Omarchy's lock screen; verified, stored in the keyring
glancekey-agent pair              # shows the QR code to scan with the iPhone Camera
glancekey-agent status
```
Logs: `journalctl --user -u glancekey-agent -f`

### Pairing
On the Mac click **Pair iPhone…**; on Linux run `glancekey-agent pair`. Then scan the QR code with the iPhone Camera app.

## Approve sudo with your iPhone

Optional. `sudo` (and, on Linux, polkit's admin dialogs) first waits for your iPhone:

```
$ sudo pacman -Syu
GlanceKey: approve on your iPhone, or wait 30 s to type your password.
GlanceKey: approved on Ruben's iPhone.
```

Open GlanceKey (or tap the notification): it shows `sudo pacman -Syu` and approves it with Face ID. **Deny**, no answer within 30 s, or no connection: the normal password prompt follows. SSH sessions get the password prompt straight away.

Set it up after pairing, and again after pairing another iPhone or updating GlanceKey:
- **Linux:** `sudo glancekey-agent enable-sudo`. It copies the agent to `/usr/local/libexec/glancekey/`, saves your paired iPhones in `/etc/glancekey/approvers.json` and adds one `pam_exec` line to `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. polkit keeps its config in `/usr/lib/pam.d` on Arch and Debian, so it creates the `/etc/pam.d/polkit-1` override from that; run it again after polkit updates. Undo: `sudo glancekey-agent disable-sudo`.
- **Mac:** `scripts/enable-mac-sudo.sh` (needs Go and the Xcode command line tools). It builds the checker and a small PAM module, tests the module with PAM, then adds it to `/etc/pam.d/sudo_local`, which survives macOS updates. Undo: `scripts/enable-mac-sudo.sh --disable`. If sudo ever stops working, this undoes it without sudo:
  `osascript -e 'do shell script "rm /etc/pam.d/sudo_local" with administrator privileges'`

How it works: PAM runs the checker (`glancekey-agent pam`) as root. It asks the GlanceKey agent or Mac app to show the request on your iPhone, then verifies the iPhone's signature against `approvers.json`. Problems are logged to syslog under `glancekey` (`journalctl -t glancekey`).

**Notifications:** in the iPhone app, turn on **Notify me with ntfy** and subscribe to the topic it shows in the free [ntfy app](https://apps.apple.com/app/ntfy/id1625396347). Computers then post "… is waiting for you" to it; tap it to open GlanceKey. Only the computer's name goes through ntfy.

On Linux this is mostly a convenience: the login password the agent keeps for Omarchy's lock screen is in the GNOME keyring, which any program running as you can read, and on Linux it's also your sudo password.

## Mac password dialogs

When a Mac dialog asks for your password, the Mac app puts it on your iPhone (and notifies ntfy). Tap **Approve** and look at the phone: the Mac app types your saved login password into the dialog and submits it. **Deny** presses Cancel. Handle the dialog on the Mac instead and the request disappears from the phone.

It covers two kinds of dialogs:
- "… is trying to unlock" with **Use Password…** (LocalAuthentication, `coreautha`): 1Password, Safari passwords, and other apps that use Touch ID.
- Administrator dialogs (`SecurityAgent`): System Settings, installers, `osascript … with administrator privileges`.

Turn it off with **Fill in password dialogs from iPhone** in the menu bar item. It needs the saved password and Accessibility access.

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
(cd linux && go build -o /tmp/glancekey-agent .)
GLANCEKEY_CONFIG_DIR=/tmp/fu /tmp/glancekey-agent run &
GLANCEKEY_CONFIG_DIR=/tmp/fu /tmp/glancekey-agent pair     # prints glancekey://pair?d=…
swift run --package-path Core fake-phone pair 'glancekey://pair?d=…'
swift run --package-path Core fake-phone lock|unlock|status|test-replay|test-bad-signature
swift run --package-path Core fake-phone hello                    # lock state and waiting approvals

# Approvals without root: run the checker like PAM would, against that agent, and answer with fake-phone.
echo '{"command":"approvers"}' | nc -U /tmp/fu/agent.sock   # save .approvers as approvers.json in a 0755 folder
PAM_USER=$USER PAM_SERVICE=sudo /tmp/glancekey-agent pam --approvers <dir>/approvers.json --socket /tmp/fu/agent.sock &
swift run --package-path Core fake-phone approve --wait 10       # or deny, approve-tampered
# The Mac PAM module the same way (build it as scripts/enable-mac-sudo.sh does):
build/mac-sudo/pam-check --direct build/mac-sudo/pam_glancekey.so.2 /tmp/glancekey-agent --approvers … --socket …
```

`project.yml` is the source of truth for the Xcode project (`xcodegen generate`). The app's name is set in a few places listed in `Core/Sources/AppCore/Brand.swift`; `scripts/test.sh` checks they agree. The Mac app's relay can be overridden with `defaults write nl.dinkelworks.glancekey.mac relayURL http://localhost:8787`.
