#!/bin/sh
# Installs GlanceKey for Linux and starts it with your session. Run it again to update.
#   curl -fsSL https://www.glancekey.com/install.sh | sh
# It installs into ~/.local/bin (or $XDG_BIN_HOME) and doesn't need root. Docs: https://www.glancekey.com/docs#linux
set -eu

downloads=https://download.glancekey.com
case "$(uname -s) $(uname -m)" in
  "Linux x86_64" | "Linux amd64") arch=amd64 ;;
  "Linux aarch64" | "Linux arm64") arch=arm64 ;;
  *) echo "GlanceKey for Linux needs Linux on x86-64 or ARM64, not $(uname -sm)." >&2; exit 1 ;;
esac
file=glancekey-agent-linux-$arch
bin=${XDG_BIN_HOME:-$HOME/.local/bin}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Downloading GlanceKey for Linux ($arch)…"
curl -fsSL "$downloads/$file" -o "$work/$file"
curl -fsSL "$downloads/SHA256SUMS" -o "$work/SHA256SUMS"
if ! (cd "$work" && grep "  $file\$" SHA256SUMS | sha256sum -c --status); then
  echo "The download doesn't match its checksum, so it isn't installed. Try again later." >&2
  exit 1
fi
mkdir -p "$bin"
install -m 755 "$work/$file" "$bin/glancekey-agent"
echo "Installed $bin/glancekey-agent, version $("$bin/glancekey-agent" version)."

if systemctl --user show-environment >/dev/null 2>&1; then
  "$bin/glancekey-agent" install-service
  systemctl --user restart glancekey-agent.service  # so an update takes over right away
else
  echo "There's no systemd user session here, so it isn't started. Start it with: glancekey-agent run"
fi

case ":$PATH:" in
  *":$bin:"*) ;;
  *) echo "Add $bin to your PATH to run glancekey-agent from anywhere." ;;
esac
echo
echo "Next, save your login password (for the lock screen) and pair your iPhone:"
echo "  glancekey-agent set-password"
echo "  glancekey-agent pair"
