#!/bin/sh
# Copy the datu binary into the built Flutter macOS app so it is self-contained.
# The app spawns it as its private wallet service (or attaches to a running one).
#
#   apps/wallet/tool/bundle_bridge.sh [path/to/app.app]
set -eu

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP="${1:-$ROOT/apps/wallet/build/macos/Build/Products/Debug/datu_wallet.app}"
BIN="${DATU_BIN:-$ROOT/target/debug/datu}"

if [ ! -d "$APP" ]; then
  echo "app not built: $APP" >&2
  echo "run: cd apps/wallet && flutter build macos --debug" >&2
  exit 1
fi
if [ ! -x "$BIN" ]; then
  echo "binary not found: $BIN" >&2
  exit 1
fi

mkdir -p "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/Resources/datu"
chmod +x "$APP/Contents/Resources/datu"
echo "bundled $BIN -> $APP/Contents/Resources/datu"
