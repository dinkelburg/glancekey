#!/bin/zsh
# Checks that the app's name is the same everywhere it's defined and spelled out nowhere else, so renaming the app
# stays a matter of the places Core/Sources/AppCore/Brand.swift lists. Docs (*.md) and the website (site/) may use the
# name freely.
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

if [[ -z $APP_NAME || -z $APP_ID ]]; then
  echo "project.yml has no APP_NAME or APP_ID" >&2
  exit 1
fi
relay_host=$(sed -n 's#.*static let relay = URL(string: "https://\([^"]*\)").*#\1#p' Core/Sources/AppCore/Brand.swift)

problems=()
# needs <file> <extended regex>: the file must have a matching line.
needs() { grep -qE -- "$2" "$1" || problems+=("$1 should match: $2") }
needs project.yml "^name: $APP_NAME\$"
needs Core/Sources/AppCore/Brand.swift "static let name = \"$APP_NAME\""
needs Core/Sources/AppCore/Brand.swift "static let id = \"$APP_ID\""
needs linux/brand.go "appName += \"$APP_NAME\""
needs linux/brand.go "appID += \"$APP_ID\""
needs linux/brand.go "defaultRelay += \"https://$relay_host\""
needs relay/src/index.ts "^const APP_NAME = \"$APP_NAME\";"
needs relay/wrangler.jsonc "\"name\": \"$APP_ID-relay\""
needs relay/wrangler.jsonc "\"pattern\": \"$relay_host\""
needs relay/wrangler.jsonc "\"APNS_TOPIC\": \"$BUNDLE_ID\""

definitions=(project.yml Core/Sources/AppCore/Brand.swift linux/brand.go relay/wrangler.jsonc)
stray=$(git grep --untracked -n -i -e "$APP_ID" -- . ':!*.md' ':!site' ${definitions/#/:!} |
  grep -v '^relay/src/index.ts:[0-9]*:const APP_NAME = ' || true)

if (( ${#problems} )) || [[ -n $stray ]]; then
  for problem in $problems; do echo "$problem" >&2; done
  [[ -z $stray ]] || echo "Use the name from Brand.swift, brand.go or project.yml instead of spelling it out:\n$stray" >&2
  exit 1
fi
echo "$APP_NAME ($APP_ID) is defined consistently"
