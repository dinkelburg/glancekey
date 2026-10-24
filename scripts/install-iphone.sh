#!/bin/zsh
# Builds FaceUnlock for iPhone and installs it on a paired iPhone (USB, or Wi-Fi once paired in Xcode).
# Usage: scripts/install-iphone.sh [device-udid]
# With a free Apple developer account the app stops opening after 7 days; run this again to renew it.
set -euo pipefail
cd "${0:A:h}/.."

udid=${1:-}
if [[ -z $udid ]]; then
  devices_json=$(mktemp)
  xcrun devicectl list devices --json-output "$devices_json" >/dev/null
  udid=$(python3 -I - "$devices_json" <<'PY'
import json, sys
devices = json.load(open(sys.argv[1]))["result"]["devices"]
for d in devices:
    properties = d.get("properties", {})
    hw = properties.get("hardware", d.get("hardwareProperties", {}))
    connection = properties.get("connection", d.get("connectionProperties", {}))
    # devicectl also lists paired Simulators; only install on a physical iPhone.
    if (hw.get("platform") == "iOS" and hw.get("deviceType") == "iPhone"
            and hw.get("reality", "physical") != "simulated" and connection.get("pairingState") == "paired"):
        print(hw["udid"])
        break
PY
)
  rm -f "$devices_json"
fi
if [[ -z $udid ]]; then
  echo "No paired iPhone found. Connect it with a cable, unlock it and tap Trust, then try again." >&2
  exit 1
fi

xcodegen generate --quiet
xcodebuild -project FaceUnlock.xcodeproj -scheme FaceUnlockiOS -configuration Release \
  -destination "platform=iOS,id=$udid" -derivedDataPath build/DerivedData \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration -quiet build

app=build/DerivedData/Build/Products/Release-iphoneos/FaceUnlock.app
xcrun devicectl device install app --device "$udid" "$app"
xcrun devicectl device process launch --device "$udid" nl.dinkelworks.faceunlock || \
  echo "Installed. If it won't open, trust the developer in Settings › General › VPN & Device Management."
