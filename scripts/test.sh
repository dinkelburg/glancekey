#!/bin/zsh
# Runs every test suite: the Swift core (incl. vectors shared with Go), the Linux agent and the relay.
set -euo pipefail
cd "${0:A:h}/.."

echo "== Swift core"
swift test --package-path Core

echo "== Linux agent"
(cd linux && go vet ./... && GOOS=linux go vet ./... && go test ./...)

echo "== Relay"
cd relay
[[ -d node_modules ]] || npm ci --no-fund --no-audit
npx wrangler types >/dev/null
npx tsc --noEmit
npm test
