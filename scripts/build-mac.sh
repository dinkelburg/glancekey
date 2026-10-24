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
mkdir -p "$HOME/Applications"
rm -rf "$installed"
ditto "$built" "$installed"
open "$installed"
echo "Installed and started $installed"
