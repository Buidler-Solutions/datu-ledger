#!/bin/sh
# Copy the datu binary (desktop bridge sidecar) and, when built, the native
# wallet core dylib into the Flutter macOS app so it is self-contained.
#
#   apps/wallet/tool/bundle_bridge.sh [path/to/app.app]
set -eu

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP="${1:-$ROOT/apps/wallet/build/macos/Build/Products/Debug/datu_wallet.app}"
BIN="${DATU_BIN:-$ROOT/target/debug/datu}"
DYLIB="${DATU_WALLET_FFI:-$ROOT/target/debug/libdatu_wallet_ffi.dylib}"

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

if [ -f "$DYLIB" ]; then
  cp "$DYLIB" "$APP/Contents/Resources/libdatu_wallet_ffi.dylib"
  echo "bundled $DYLIB -> $APP/Contents/Resources/libdatu_wallet_ffi.dylib"
  echo "native-core demo: DATU_WALLET_FFI=$APP/Contents/Resources/libdatu_wallet_ffi.dylib open the app"
else
  echo "native core dylib not found (optional): cargo build -p datu-wallet-ffi"
fi
