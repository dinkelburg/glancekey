#!/bin/zsh
# Lets sudo on this Mac wait for an approval from your iPhone (FaceUnlock app) before asking for the password.
# Builds the checker and the PAM module, then installs them with sudo (asks for your password once):
#   /usr/local/libexec/faceunlock/faceunlock-agent   the checker, which verifies the iPhone's signature
#   /usr/local/lib/pam/pam_faceunlock.so.2           runs the checker for sudo
#   /etc/faceunlock/approvers.json                   the paired iPhones, from the running FaceUnlock app
#   /etc/pam.d/sudo_local                            one `auth sufficient` line (survives macOS updates)
# PAM is tested with the module before sudo_local changes. If sudo ever breaks, undo it without sudo:
#   osascript -e 'do shell script "rm /etc/pam.d/sudo_local" with administrator privileges'
#
# Usage: scripts/enable-mac-sudo.sh             set up, or update after pairing another iPhone
#        scripts/enable-mac-sudo.sh --disable   undo
set -euo pipefail
cd "${0:A:h}/.."

out=build/mac-sudo
mkdir -p $out
(cd linux && CGO_ENABLED=0 go build -trimpath -o ../$out/faceunlock-agent .)
flags=(-Wall -Wextra -Wno-unused-parameter -Werror -O2)
clang -shared $flags -arch arm64 -arch x86_64 -o $out/pam_faceunlock.so.2 Mac/PAM/pam_faceunlock.c -lpam
clang $flags -o $out/pam-check Mac/PAM/pam_check.c -lpam

if [[ ${1:-} == --disable ]]; then
  sudo $out/faceunlock-agent disable-sudo
else
  sudo $out/faceunlock-agent enable-sudo --module $out/pam_faceunlock.so.2 --pam-check $out/pam-check
fi
