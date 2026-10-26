#!/bin/zsh
# Builds a release of the Mac app and the Linux program and publishes it on the downloads site (DOWNLOADS in
# scripts/brand.sh, served by site/downloads), then updates the Homebrew tap (scripts/update-homebrew.sh):
#   <name>-<version>.dmg, <name>.dmg    the Mac app, signed with Developer ID and notarized by Apple, in a disk
#                                       image to drag it to Applications
#   <id>-agent-linux-amd64, -arm64      the Linux program (also as <id>-agent-<version>-linux-…)
#   SHA256SUMS
# For a new version, raise MARKETING_VERSION in project.yml first. The iPhone app goes through App Store Connect
# instead (scripts/upload-testflight.sh).
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

out=build/downloads
work=build/release
rm -rf $out $work
mkdir -p $out $work

# The Mac app: archive, send it to Apple for notarization, then export the notarized app.
xcodegen generate --quiet
xcodebuild -project $APP_NAME.xcodeproj -scheme MacApp -configuration Release -destination 'generic/platform=macOS' \
  -archivePath $work/$APP_NAME.xcarchive -derivedDataPath build/DerivedData \
  CURRENT_PROJECT_VERSION=$(date +%Y%m%d.%H%M) -allowProvisioningUpdates -quiet archive
cat > $work/export.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>developer-id</string>
  <key>destination</key><string>upload</string>
  <key>signingStyle</key><string>automatic</string>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath $work/$APP_NAME.xcarchive -exportPath $work/upload \
  -exportOptionsPlist $work/export.plist -allowProvisioningUpdates -quiet
echo "Waiting for Apple to notarize the Mac app…"
for attempt in {1..60}; do
  if result=$(xcodebuild -exportNotarizedApp -archivePath $work/$APP_NAME.xcarchive -exportPath $work/notarized 2>&1); then
    break
  elif [[ $result != *"not ready for distribution"* || $attempt == 60 ]]; then
    print -r -- "$result" >&2
    exit 1
  fi
  sleep 30
done
app=$work/notarized/$APP_NAME.app
spctl --assess --type execute $app  # Gatekeeper opens it without a warning
# The disk image itself isn't signed: Xcode keeps the Developer ID key in Apple's cloud. Gatekeeper checks the app
# inside, which carries its notarization ticket. dmgbuild lays out the window without scripting Finder.
[[ -x build/dmgbuild/bin/dmgbuild ]] || { python3 -m venv build/dmgbuild && build/dmgbuild/bin/pip install -q dmgbuild==1.6.7 }
build/dmgbuild/bin/dmgbuild -s scripts/dmg-settings.py -D app=$app $APP_NAME $out/$APP_NAME-$VERSION.dmg \
  > /dev/null 2> >(grep -v 'is deprecated' >&2)  # hdiutil's warnings on macOS 27
cp $out/$APP_NAME-$VERSION.dmg $out/$APP_NAME.dmg

# The Linux program.
scripts/build-linux.sh >/dev/null
for arch in amd64 arm64; do
  cp build/linux/$APP_ID-agent-$arch $out/$APP_ID-agent-$VERSION-linux-$arch  # for Homebrew
  cp build/linux/$APP_ID-agent-$arch $out/$APP_ID-agent-linux-$arch             # the latest, for install.sh
done

(cd $out && shasum -a 256 * > SHA256SUMS)
# The bare address leads to the download page.
print -- "/ $WEBSITE/download 302" > $out/_redirects
(cd site && npx wrangler deploy -c downloads/wrangler.jsonc)

scripts/update-homebrew.sh
echo "Released $APP_NAME $VERSION on $DOWNLOADS"
