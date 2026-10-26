#!/bin/zsh
# Builds what sudo approvals need on a Mac, as universal binaries (Apple silicon and Intel), into <folder>:
#   <id>-agent      the checker, which verifies the iPhone's signature (the Go program in linux/)
#   pam_<id>.so.2   the PAM module that runs it for sudo (Mac/PAM)
#   pam-check       tests the module with PAM before sudo_local changes
# The Mac app carries them in Contents/Helpers (project.yml); scripts/enable-mac-sudo.sh uses them directly.
# Usage: scripts/build-mac-helpers.sh <folder>
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh
out=${1:?usage: scripts/build-mac-helpers.sh <folder>}

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for arch in arm64 amd64; do
  (cd linux && CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$work/agent-$arch" .)
done
lipo -create -output "$out/$APP_ID-agent" "$work/agent-arm64" "$work/agent-amd64"
flags=(-Wall -Wextra -Wno-unused-parameter -Werror -O2 -arch arm64 -arch x86_64 -mmacosx-version-min=14.0)
clang -shared $flags -o "$out/pam_$APP_ID.so.2" Mac/PAM/pam_module.c -lpam
clang $flags -o "$out/pam-check" Mac/PAM/pam_check.c -lpam
