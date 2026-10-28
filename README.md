# GlanceKey

Unlock your Mac and your Linux machine with Face ID on your iPhone, from anywhere, on any network.

```
iPhone ──HTTPS──▶ relay (relay.glancekey.com, Cloudflare) ◀──WebSocket── Mac app / Linux agent
```

- **iPhone app** (`iOS/`): tap **Unlock** in the app or on the Lock Screen card, or use Siri, Shortcuts or the Action button. Look at the phone and the computer unlocks.
  - Opening the app asks every paired computer whether it's locked or waiting for an approval (no Face ID) and lists them, with **Unlock all** for one Face ID when several are locked. Siri, Shortcuts and the Action button unlock the one locked computer straight away. While the app is open it keeps checking, so new requests show up within seconds.
  - It also approves `sudo` (and polkit dialogs on Linux) on your computers, and the Mac's password dialogs; see [Approve sudo with your iPhone](#approve-sudo-with-your-iphone) and [Mac password dialogs](#mac-password-dialogs). Approving always takes a tap on **Approve**, then Face ID.
  - Free for 2 computers and 15 unlocks and approvals a day; the subscription GlanceKey Unlimited removes both limits. See [Free version and subscription](#free-version-and-subscription).
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
- **The relay is not trusted.** It only passes messages along. It can't forge or replay an unlock or an approval, and it never sees the pairing code: the iPhone sends an HMAC proof tied to its key instead. It does see what's waiting for approval, and it could decline a request or stop passing messages on.
- **Notifications only name the computer.** A computer that waits for you asks the relay to notify your iPhone; the relay sends "… is waiting for you" through Apple's push service and stores nothing. What's waiting travels over the relay when the app asks, not in the notification. With the Lock Screen card on, the card does the notifying instead, and it does show the command (below).
- **The Lock Screen card shows what's waiting.** The relay keeps the card's contents so it can push changes (see [Lock Screen card](#lock-screen-card)): computer names and whether each is locked while the card is on, and a waiting request with its command until it's answered or expires. The card's buttons send the same signed requests as the app, with the same Face ID key. They open the app, which asks for Face ID, because iOS only lets an app do that while it's on screen; the links carry the card's own key, so a web page can't open them.
- **Relay slot:** each computer claims its slot on the relay with a secret, so nobody else can connect in its place.
- **Login passwords stay on each computer:**
  - Mac: in the login keychain.
  - Linux: encrypted to each paired iPhone (`linux/seal.go`, `Core/Sources/AppCore/PasswordSeal.swift`). Each iPhone has a second Secure Enclave key per computer, its password key, which also only works after Face ID. The agent encrypts the password to it and keeps only that, so a copy of its files is useless without the iPhone. To unlock, hello sends a one-time session key; the iPhone works out the key that opens the password and sends it back encrypted to that session key, signed with the command. The iPhone never sees the password, and the relay sees neither the password nor its key. A relay that swaps the session key gets that one key at most (the signature check then fails the unlock), and it opens nothing without the agent's files; after every unlock the agent seals the password again under a fresh key anyway. A plain copy stays in the GNOME keyring until every paired iPhone has opened its own encrypted copy once, so there's a way back if a password key doesn't work: an iPhone on an app version from before this has none, and an updated app registers its password key with its next command.
  - Each is checked against your account before it's typed (OpenDirectory on the Mac, `unix_chkpwd` on Linux).
  - On the Mac, the same keychain item lists the iPhones that may use it. Other programs running as you can overwrite keychain items (without reading them) and the app's settings, but they don't know your password. So an iPhone added behind the app's back can't unlock or approve anything; the menu marks it. When the list can't be checked that way (you changed your Mac password, so the old one no longer works), saving the new password asks you to confirm each iPhone in the menu, by its key's fingerprint, which the iPhone app shows on the computer's page.
  - The Mac app runs with the hardened runtime and without the debugging entitlement, so other programs can't load code into it or read its memory.
  - Typing stops if the screen unlocks partway through, so the password can't end up in an app.
- **Approvals are checked as root:** for `sudo`, a root-owned checker verifies the iPhone's signature itself, against a root-owned list of iPhones. The app or agent in between only passes messages, so neither it nor anything running as you can approve. The iPhone signs exactly the command it showed you: invisible characters and invalid text show as escapes, and a command too long to show in full, or one the checker can't read for certain, gets the password prompt instead. Setting it up shows which iPhones it will trust, with their keys' fingerprints, and which of them are new.
- **Password dialogs are filled like the lock screen:** the Mac app checks the iPhone's signature as for an unlock. It only types into Apple-signed dialog processes (checked by code signature), and the keystrokes go to that process alone, never to the app in front, and only into the dialog you approved. Keychain prompts for GlanceKey's own items (another program asking for the saved password) never reach the iPhone.

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
glancekey-agent set-password      # needed for Omarchy's lock screen; verified, then encrypted to your iPhones
glancekey-agent pair              # shows the QR code to scan with the iPhone Camera
glancekey-agent status
```
Logs: `journalctl --user -u glancekey-agent -f`

### Pairing
On the Mac click **Pair iPhone…**; on Linux run `glancekey-agent pair`. Then scan the QR code with the iPhone Camera app.

### Your own relay
`relay/wrangler.jsonc` deploys the public relay. For your own Cloudflare account, remove `account_id` there and replace the two `routes` with your own domain (or remove them for a workers.dev address). Then `cd relay && npm install && npx wrangler deploy`, and point your computers at it:
- Mac: `defaults write nl.dinkelworks.glancekey.mac relayURL https://relay.example.com`, then quit and reopen the app.
- Linux: set `"relay"` in `~/.config/glancekey/agent.json`, then `systemctl --user restart glancekey-agent`.

Pair again afterwards; the QR code carries the relay's address, so the iPhone follows. Notifications need your own APNs key and iPhone app build (see [Notifications](#notifications)).

## Approve sudo with your iPhone

Optional. `sudo` (and, on Linux, polkit's admin dialogs) first waits for your iPhone:

```
$ sudo pacman -Syu
GlanceKey: approve on your iPhone, or press Enter to type your password (it waits 30 seconds).
GlanceKey: approved on Ruben's iPhone.
```

Open GlanceKey (or tap the notification): it shows `sudo pacman -Syu` and approves it with Face ID. **Deny**, Enter in the terminal, no answer in time, or no connection: the normal password prompt follows. SSH sessions get the password prompt straight away, and so does a request whose command the checker can't read for certain. polkit doesn't tell PAM what a dialog is for, so for those the iPhone only says a password dialog is waiting; the dialog on your screen says what it's for.

How long it waits is a setting of each computer: 30 seconds (the default), 1, 5 or 15 minutes, or until you answer. Set it on the computer's page in the iPhone app (after Face ID; the computer checks the iPhone's signature over the value), in the Mac menu (**Wait for iPhone**), or on Linux with `glancekey-agent set-wait 30s|1m|5m|15m|until-answered`. The Mac app or the agent saves it and hands it to the checker with each request; it only decides how long the checker waits, never whether it approves. Mac password dialogs wait as long.

Set it up after pairing, and again after pairing another iPhone or updating GlanceKey:
- **Linux:** `sudo "$(command -v glancekey-agent)" enable-sudo` (the full path, because sudo on Debian, Ubuntu and Fedora doesn't search `~/.local/bin`; `sudo glancekey-agent enable-sudo` works on Arch). It lists the iPhones it will trust with each key's fingerprint and pairing date, marking new ones, and asks before it changes anything. Every iPhone is called "iPhone", so compare the fingerprints with the one the iPhone app shows on the computer's page. It copies the agent to `/usr/local/libexec/glancekey/`, saves your paired iPhones in `/etc/glancekey/approvers.json` and adds one `pam_exec` line to `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. polkit keeps its config in `/usr/lib/pam.d` on Arch and Debian, so it creates the `/etc/pam.d/polkit-1` override from that; run it again after polkit updates. Undo: `sudo glancekey-agent disable-sudo`.
- **Mac:** **Turn on…** next to sudo in the GlanceKey menu, **Update…** after pairing or removing an iPhone, or updating. The app carries the checker, a small PAM module and `pam-check` in `Contents/Helpers` (`scripts/build-mac-helpers.sh`). It checks its own signature, which covers them, and notes their code hashes. As root it copies them to a root-owned folder, checks they're signed by the app's own team and have those hashes (so no older signed version can be swapped in), tests the module by loading it as sudo would (`pam-check --direct`), then adds it to `/etc/pam.d/sudo_local`, which survives macOS updates.
  - macOS protects `/etc/pam.d` ("administer your computer"): it only lets a change through when it can ask you, and it can't for a script run through the administrator prompt. So the first **Turn on…** runs the same script in Terminal (a `.command` file), where `enable-sudo --ask` lists the iPhones with their keys' fingerprints and asks first. **Update…** leaves `sudo_local` alone when the line is already there, so it works through the administrator prompt, which names the iPhones.
  - **Turn off…** goes through the administrator prompt too. When macOS keeps it out of `/etc/pam.d` it removes `approvers.json`, so the checker sends sudo straight to the password, and leaves the line, the checker and the module (sudo must still find the module); **Remove the line in Terminal…** runs `disable-sudo` there to take them out. From the source, `scripts/enable-mac-sudo.sh` does the same (`--disable` to undo). If sudo ever stops working, this undoes it without sudo:
  `osascript -e 'do shell script "rm /etc/pam.d/sudo_local" with administrator privileges'`

How it works: PAM runs the checker (`glancekey-agent pam`) as root. It asks the GlanceKey agent or Mac app to show the request on your iPhone, then verifies the iPhone's signature against `approvers.json`. Problems are logged to syslog under `glancekey` (`journalctl -t glancekey`).

**Notifications:** in the iPhone app, turn on **Notify me**. When a computer waits for you, your iPhone gets "… is waiting for you"; tap it to open GlanceKey. The relay sends it through Apple's push service (see [Notifications](#notifications)).

On Linux this is mostly a convenience: your sudo password is your login password, and a program running as you has ways to catch it, for example the next time it's typed (by you, or by the agent on the lock screen).

## Mac password dialogs

When a Mac dialog asks for your password, the Mac app puts it on your iPhone (and notifies it). Tap **Approve** and look at the phone: the Mac app types your saved login password into the dialog and submits it. **Deny** presses Cancel. Handle the dialog on the Mac instead and the request disappears from the phone.

It covers two kinds of dialogs:
- "… is trying to unlock" with **Use Password…** (LocalAuthentication, `coreautha`): 1Password, Safari passwords, and other apps that use Touch ID.
- Administrator dialogs (`SecurityAgent`): System Settings, installers, `osascript … with administrator privileges`.

Turn it off with **Fill in password dialogs from iPhone** in the menu bar item. It needs the saved password and Accessibility access.

## Lock Screen card

The iPhone shows your computers on the Lock Screen and in the Dynamic Island (a Live Activity): which are locked, and requests such as sudo, with **Unlock**, **Lock** and **Approve**. The buttons open GlanceKey, which asks for Face ID and does it straight away: iOS doesn't let an app ask for Face ID from the Lock Screen. That's only when the card showed the whole command (and the computer's name the app knows): the links carry a digest of what the card showed. A command too long for the card opens in the app, where you tap **Approve**. To deny a request, tap it to open it in the app. A button that's working shows a progress ring on the card. Turn it off with **Show on the Lock Screen** in the app.

How it stays current:
- The iPhone app makes a card secret; the card's id on the relay is its SHA-256. It registers the card at `POST /v1/card/<id>` (`iOS/LiveCardController.swift`): the computers it lists, a key for the card's links, and Apple's tokens to start a card and to update the running one. It gives the computers only the id, in `hello`.
- Each computer sends `{"card": {"cards", "locked", "approvals"}}` over its WebSocket whenever that changes (`linux/card.go`, `Mac/AppModel.swift`). It checks the lock screen every few seconds while an iPhone has a card.
- The relay's `Card` Durable Object keeps the latest part of each computer, marks a computer offline when its connection goes, drops requests when they expire, and pushes the whole card with the APNs key (`apns-push-type: liveactivity`), at most once a second.
- iOS ends a Live Activity after eight hours. The relay then starts a new one (push-to-start) when a computer locks, comes back locked, or asks for something, at most every ten minutes, and iOS wakes the app to register the new card's update token. Opening the app also starts one.
- Computers on an older version don't send their part; the card shows what the app last saw for them.

Like notifications, the card needs the relay's APNs key, so a self-hosted relay needs your own app build; without it, the card only changes while the app is open.

## Notifications

The iPhone app gets a push token from Apple and gives it to its computers in every `hello`. A computer that starts waiting for an approval sends `{"notify": {"machineName", "pushTokens"}}` over its WebSocket, and the relay pushes the notification with the app's APNs key. It tries production first and the sandbox second, because an app installed from Xcode has a sandbox token. A newer notification for the same computer replaces the older one. Apple keeps trying to deliver it for as long as the request waits (`expiresIn`, two minutes from older computers). A computer can send six a minute, and one iPhone gets at most ten a minute and sixty an hour from all computers together: a `Recipient` Durable Object per push token counts them for an hour, under the token's SHA-256, and keeps nothing else.

An iPhone with a Lock Screen card gets no notification from its computers: the card registration tells the relay whether notifications are on (`alerts`) and the push token. For a new request, the relay sends the card's update with an alert (it lights up the iPhone, shows the card and plays the sound), and only sends the regular notification when there's no card to do that: none started yet, or ended and not started again. A card you swiped away isn't something the relay can see, so a request then shows up silently.

Setting up the key (once, or after revoking it):
1. In the Apple Developer account, Certificates, Identifiers & Profiles › Keys › +: name it, tick **Apple Push Notifications service (APNs)**, and download `AuthKey_<key id>.p8`. Apple only lets you download it once; keep it in 1Password.
2. Put the key ID and the team ID in `relay/wrangler.jsonc` (`APNS_KEY_ID`, `APNS_TEAM_ID`), and the key itself in a secret: `cd relay && npx wrangler secret put APNS_KEY < AuthKey_<key id>.p8`.
3. `npx wrangler deploy`.

Without the key the relay works as before and only logs that it can't notify. A self-hosted relay needs your own app build and key, since APNs only delivers to apps of the key's team. `wrangler dev` can't reach APNs (it needs HTTP/2), so notifications only work from a deployed relay.

## Free version and subscription

The App Store app is free for 2 computers and 15 unlocks and approvals a day (all computers together, from midnight to midnight on the iPhone). **GlanceKey Unlimited**, an auto-renewing App Store subscription (€2.99 a month or €24.99 a year, no trial), removes both limits. It's in the app's Settings, and the app offers it when you reach a limit, before Face ID.

- **Counted on the iPhone** (`iOS/Store.swift`, `Core/Sources/AppCore/FreeTier.swift`). Only successful unlocks and approvals count, and **Unlock all** counts one per computer; locking and denying are free. At the limit, the computer just asks for its password as usual.
- **Apple checks the subscription on the iPhone** with StoreKit, so neither the use nor the purchase reaches the relay or us, and pairing still needs no account.
- **The relay says how many** (`GET /v1/limits`, `FREE_LIMITS` in `relay/wrangler.jsonc`), so the numbers change with a relay deploy instead of App Review. The app keeps the last answer, and 2 and 15 until it has one.
- **Only on our relay, only in the App Store app.** Computers on a relay of your own have no limits, and neither has a copy you build and install yourself (it carries a provisioning profile, App Store and TestFlight installs don't). The simulator has the limits, for testing.
- **Testing:** run `PhoneApp` from Xcode; its scheme uses `iOS/Unlimited.storekit`, so the subscription works without App Store Connect (Debug › StoreKit › Manage Transactions to cancel or refund). TestFlight purchases are free.
- **App Store Connect:** subscription group "GlanceKey Unlimited" with `nl.dinkelworks.glancekey.unlimited.yearly` and `.monthly` (`Store.productIDs`), at the same level. Terms of use: Apple's standard EULA.

## Limitations

- **The computer has to be awake and logged in.**
  - After a restart, type your password once yourself.
  - A sleeping computer can't be reached. On the Mac, "Keep Mac awake on power adapter" (on by default) prevents idle sleep while it's charging.
- **Linux on Omarchy needs `wtype`, and `secret-tool` with an unlocked GNOME keyring** for the password until every paired iPhone has its own encrypted copy. Omarchy ships all three.

## Releases

- **iPhone:** `scripts/upload-testflight.sh` uploads a build to App Store Connect (TestFlight, then App Store review).
- **Mac and Linux:** raise `MARKETING_VERSION` in `project.yml` (the iPhone app has its own, `IPHONE_VERSION`), then run `scripts/release.sh`. It archives the Mac app, has Apple notarize it (Developer ID) and puts it in a disk image (`scripts/dmg-settings.py`), builds the Linux program, publishes everything with checksums on https://download.glancekey.com (the `site/downloads` Worker, files from `build/downloads`, not in git) and updates the Homebrew tap (`scripts/update-homebrew.sh`, https://github.com/dinkelburg/homebrew-glancekey). Then update the website if anything users see changed.

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
PAM_USER=$USER PAM_SERVICE=test /tmp/glancekey-agent pam --approvers <dir>/approvers.json --socket /tmp/fu/agent.sock &
swift run --package-path Core fake-phone approve --wait 10       # or deny, approve-tampered
# The Mac PAM module the same way (build it as scripts/enable-mac-sudo.sh does):
build/mac-sudo/pam-check --direct build/mac-sudo/pam_glancekey.so.2 /tmp/glancekey-agent --approvers … --socket …
```

`project.yml` is the source of truth for the Xcode project (`xcodegen generate`). The app's name is set in a few places listed in `Core/Sources/AppCore/Brand.swift`; `scripts/test.sh` checks they agree. The Mac app's relay can be overridden with `defaults write nl.dinkelworks.glancekey.mac relayURL http://localhost:8787`.

## Security

Found a security problem? Report it privately, not in a public issue: see [SECURITY.md](SECURITY.md).

## Contributing

Bug reports and ideas are welcome as GitHub issues. Pull requests aren't accepted for now: the App Store version may only contain code Ruben Dinkelman owns, so outside code would first need a contributor agreement.

## License

GlanceKey is free software under the [GNU Affero General Public License v3.0](LICENSE). You may use, change and share it. If you share a changed version, or run a changed relay for other people, you have to publish your changes under the same license.

The license covers the code, not the GlanceKey name, logo or app icon. If you publish your own version, give it its own name and icon; the name is set in the few files `Core/Sources/AppCore/Brand.swift` lists.
