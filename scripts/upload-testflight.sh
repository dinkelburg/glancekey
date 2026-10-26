#!/bin/zsh
# Archives the iPhone app and uploads it to App Store Connect, where it shows up in TestFlight after Apple
# processes it (a few minutes) and can later be submitted to the App Store.
# Every upload needs a higher build number, so it uses the date and time.
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

build=$(date +%Y%m%d.%H%M)
archive=build/$APP_NAME.xcarchive
export_options=$(mktemp)
trap 'rm -f "$export_options"' EXIT
cat > "$export_options" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>signingStyle</key><string>automatic</string>
  <key>uploadSymbols</key><true/>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST

xcodegen generate --quiet
rm -rf "$archive"
xcodebuild -project $APP_NAME.xcodeproj -scheme PhoneApp -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$archive" -derivedDataPath build/DerivedData \
  CURRENT_PROJECT_VERSION=$build -allowProvisioningUpdates -quiet archive
xcodebuild -exportArchive -archivePath "$archive" -exportPath build/upload \
  -exportOptionsPlist "$export_options" -allowProvisioningUpdates
echo "Uploaded build $build. TestFlight shows it once App Store Connect has processed it."
