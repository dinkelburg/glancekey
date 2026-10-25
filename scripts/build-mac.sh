#!/bin/zsh
# Builds FaceUnlock for Mac, installs it as ~/Applications/FaceUnlock.app and (re)starts it.
set -euo pipefail
cd "${0:A:h}/.."

xcodegen generate --quiet
xcodebuild -project FaceUnlock.xcodeproj -scheme FaceUnlockMac -configuration Release \
  -derivedDataPath build/DerivedData -allowProvisioningUpdates -quiet build

built=build/DerivedData/Build/Products/Release/FaceUnlock.app
installed=$HOME/Applications/FaceUnlock.app

pkill -x FaceUnlock || true
# Opening it again before the old copy has quit fails (LaunchServices -600).
for _ in {1..50}; do pgrep -x FaceUnlock >/dev/null || break; sleep 0.1; done
mkdir -p "$HOME/Applications"
rm -rf "$installed"
ditto "$built" "$installed"
open "$installed"
echo "Installed and started $installed"
