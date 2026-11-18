#!/bin/sh
# Cross-compiles the lrecon CLI into the four bundled targets. Run from npm/.
set -eu
cd "$(dirname "$0")"
mkdir -p bin
for t in darwin-arm64 darwin-x64 linux-x64 linux-arm64 win32-x64; do
  goos=${t%-*}
  case $t in *-x64) goarch=amd64 ;; *) goarch=${t#*-} ;; esac
  ext=""
  if [ "$goos" = win32 ]; then goos=windows; ext=.exe; fi
  ( cd .. && CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -buildvcs=false \
      -ldflags="-s -w" -o "npm/bin/lrecon-$t$ext" ./lrecon/ )
done
