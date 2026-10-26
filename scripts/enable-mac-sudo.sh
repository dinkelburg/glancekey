#!/bin/zsh
# Lets sudo on this Mac wait for an approval from your iPhone before asking for the password.
# Builds the checker and the PAM module, then installs them with sudo (asks for your password once).
# The Mac app does the same from its menu with the copies it carries; this is for building from source.
# <id> is APP_ID from project.yml:
#   /usr/local/libexec/<id>/<id>-agent   the checker, which verifies the iPhone's signature
#   /usr/local/lib/pam/pam_<id>.so.2     runs the checker for sudo
#   /etc/<id>/approvers.json             the paired iPhones, from the running Mac app
#   /etc/pam.d/sudo_local                one `auth sufficient` line (survives macOS updates)
# PAM is tested with the module before sudo_local changes. If sudo ever breaks, undo it without sudo:
#   osascript -e 'do shell script "rm /etc/pam.d/sudo_local" with administrator privileges'
#
# Usage: scripts/enable-mac-sudo.sh             set up, or update after pairing another iPhone
#        scripts/enable-mac-sudo.sh --disable   undo
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

out=build/mac-sudo
scripts/build-mac-helpers.sh $out

if [[ ${1:-} == --disable ]]; then
  sudo $out/$APP_ID-agent disable-sudo
else
  sudo $out/$APP_ID-agent enable-sudo --module $out/pam_$APP_ID.so.2 --pam-check $out/pam-check
fi
