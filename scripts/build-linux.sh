#!/bin/zsh
# Cross-compiles the Linux agent into static binaries in build/linux/ (x86-64 and ARM64).
set -euo pipefail
cd "${0:A:h}/../linux"

mkdir -p ../build/linux
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" -o ../build/linux/faceunlock-agent-$arch .
done
ls -1 ../build/linux
