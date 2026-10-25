#!/bin/zsh
# Builds the Mac app, installs it in ~/Applications and (re)starts it.
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

xcodegen generate --quiet
xcodebuild -project $APP_NAME.xcodeproj -scheme MacApp -configuration Release \
  -derivedDataPath build/DerivedData -allowProvisioningUpdates -quiet build

built=build/DerivedData/Build/Products/Release/$APP_NAME.app
installed=$HOME/Applications/$APP_NAME.app

pkill -x $APP_NAME || true
# Opening it again before the old copy has quit fails (LaunchServices -600).
for _ in {1..50}; do pgrep -x $APP_NAME >/dev/null || break; sleep 0.1; done
mkdir -p "$HOME/Applications"
rm -rf "$installed"
ditto "$built" "$installed"
open "$installed"
echo "Installed and started $installed"
