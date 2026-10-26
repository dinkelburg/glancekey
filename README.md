# GlanceKey

Unlock your Mac and your Linux machine with Face ID on your iPhone, from anywhere, on any network.

```
iPhone ──HTTPS──▶ relay (relay.glancekey.com, Cloudflare) ◀──WebSocket── Mac app / Linux agent
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
- **Website** (`site/`): the landing page and privacy policy at https://www.glancekey.com. Static files; `cd site && npm run deploy` publishes them. Cloudflare Redirect Rules send glancekey.com and glancekey.dinkel.works to www.

## How it stays safe

- **Phone key:** pairing creates a P-256 key in the iPhone's Secure Enclave. It can only sign after Face ID: there's no passcode fallback, and enrolling a new face invalidates it.
- **Every command is a challenge and response:**
  - The computer hands out a single-use nonce, valid for 60 s.
  - It only accepts a signature over that nonce, the computer's ID, the iPhone's ID and the action.
- **The relay is not trusted.** It only passes messages along. It can't forge or replay commands, and it never sees the pairing code: the iPhone sends an HMAC proof tied to its key instead.
- **Notifications only name the computer.** A computer that waits for you asks the relay to notify your iPhone; the relay sends "… is waiting for you" through Apple's push service and stores nothing. What's waiting travels over the relay when the app asks, not in the notification.
- **Relay slot:** each computer claims its slot on the relay with a secret, so nobody else can connect in its place.
- **Login passwords stay on each computer:**
  - Mac: in the login keychain. Linux: in the GNOME keyring.
  - Each is checked against your account before it's typed (OpenDirectory on the Mac, `unix_chkpwd` on Linux).
  - Typing stops if the screen unlocks partway through, so the password can't end up in an app.
- **Approvals are checked as root:** for `sudo`, a root-owned checker verifies the iPhone's signature itself, against a root-owned list of iPhones. The app or agent in between only passes messages, so neither it nor anything running as you can approve. The iPhone signs exactly the command it showed you.
- **Password dialogs are filled like the lock screen:** the Mac app checks the iPhone's signature as for an unlock. It only types into Apple-signed dialog processes (checked by code signature), and the keystrokes go to that process alone, never to the app in front.

## Setup

Users install the Mac app and the Linux program from https://www.glancekey.com/download (the docs are at https://www.glancekey.com/docs). From the source:

### Mac
1. Accept the Xcode license once: `sudo xcodebuild -license accept`
2. Run `scripts/build-mac.sh` (needs Go too: the build also makes the sudo helpers). Then, in the GlanceKey menu bar item:
   - Grant **Accessibility** access.
   - **Save** your login password.

### iPhone
1. Connect it with a cable and enable Developer Mode.
2. Run `scripts/install-iphone.sh`.

It's signed for development with the Apple Developer Program team, so it keeps opening for a year. Re-run the script to renew it.

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
- **Mac:** **Turn on…** next to sudo in the GlanceKey menu (it asks for an administrator password; **Update…** after pairing another iPhone or updating). The app carries the checker, a small PAM module and `pam-check` in `Contents/Helpers` (`scripts/build-mac-helpers.sh`). As root it copies them to a root-owned folder, checks they're signed by the app's own team, tests the module with PAM, then adds it to `/etc/pam.d/sudo_local`, which survives macOS updates. **Turn off…** undoes it. From the source, `scripts/enable-mac-sudo.sh` does the same (`--disable` to undo). If sudo ever stops working, this undoes it without sudo:
  `osascript -e 'do shell script "rm /etc/pam.d/sudo_local" with administrator privileges'`

How it works: PAM runs the checker (`glancekey-agent pam`) as root. It asks the GlanceKey agent or Mac app to show the request on your iPhone, then verifies the iPhone's signature against `approvers.json`. Problems are logged to syslog under `glancekey` (`journalctl -t glancekey`).

**Notifications:** in the iPhone app, turn on **Notify me**. When a computer waits for you, your iPhone gets "… is waiting for you"; tap it to open GlanceKey. The relay sends it through Apple's push service (see [Notifications](#notifications)).

On Linux this is mostly a convenience: the login password the agent keeps for Omarchy's lock screen is in the GNOME keyring, which any program running as you can read, and on Linux it's also your sudo password.

## Mac password dialogs

When a Mac dialog asks for your password, the Mac app puts it on your iPhone (and notifies it). Tap **Approve** and look at the phone: the Mac app types your saved login password into the dialog and submits it. **Deny** presses Cancel. Handle the dialog on the Mac instead and the request disappears from the phone.

It covers two kinds of dialogs:
- "… is trying to unlock" with **Use Password…** (LocalAuthentication, `coreautha`): 1Password, Safari passwords, and other apps that use Touch ID.
- Administrator dialogs (`SecurityAgent`): System Settings, installers, `osascript … with administrator privileges`.

Turn it off with **Fill in password dialogs from iPhone** in the menu bar item. It needs the saved password and Accessibility access.

## Notifications

The iPhone app gets a push token from Apple and gives it to its computers in every `hello`. A computer that starts waiting for an approval sends `{"notify": {"machineName", "pushTokens"}}` over its WebSocket, and the relay pushes the notification with the app's APNs key. It tries production first and the sandbox second, because an app installed from Xcode has a sandbox token. A newer notification for the same computer replaces the older one, they expire after two minutes, and a computer can send six a minute.

Setting up the key (once, or after revoking it):
1. In the Apple Developer account, Certificates, Identifiers & Profiles › Keys › +: name it, tick **Apple Push Notifications service (APNs)**, and download `AuthKey_<key id>.p8`. Apple only lets you download it once; keep it in 1Password.
2. Put the key ID and the team ID in `relay/wrangler.jsonc` (`APNS_KEY_ID`, `APNS_TEAM_ID`), and the key itself in a secret: `cd relay && npx wrangler secret put APNS_KEY < AuthKey_<key id>.p8`.
3. `npx wrangler deploy`.

Without the key the relay works as before and only logs that it can't notify. A self-hosted relay needs your own app build and key, since APNs only delivers to apps of the key's team. `wrangler dev` can't reach APNs (it needs HTTP/2), so notifications only work from a deployed relay.

## Limitations

- **The computer has to be awake and logged in.**
  - After a restart, type your password once yourself.
  - A sleeping computer can't be reached. On the Mac, "Keep Mac awake on power adapter" (on by default) prevents idle sleep while it's charging.
- **Linux on Omarchy needs `wtype`, `secret-tool` and an unlocked GNOME keyring.** Omarchy ships all three.

## Releases

- **iPhone:** `scripts/upload-testflight.sh` uploads a build to App Store Connect (TestFlight, then App Store review).
- **Mac and Linux:** raise `MARKETING_VERSION` in `project.yml`, then run `scripts/release.sh`. It archives the Mac app, has Apple notarize it (Developer ID), builds the Linux program, publishes everything with checksums on https://download.glancekey.com (the `site/downloads` Worker, files from `build/downloads`, not in git) and updates the Homebrew tap (`scripts/update-homebrew.sh`, https://github.com/dinkelburg/homebrew-glancekey). Then update the website if anything users see changed.

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
