#!/bin/sh
# Build "DATU Wallet.app" - a login-launched, windowless bundle that runs the
# wallet bridge so the landowner never touches a terminal.
#
#   packaging/macos/build.sh          # build the app bundle into dist/
#   packaging/macos/install.sh        # install it + a LaunchAgent (login start)
#   packaging/macos/uninstall.sh      # remove both
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/dist/DATU Wallet.app"
BIN="${DATU_BIN:-$ROOT/target/debug/datu}"

if [ ! -x "$BIN" ]; then
  echo "binary not found: $BIN (run: cargo build)" >&2
  exit 1
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>DATU Wallet</string>
  <key>CFBundleDisplayName</key><string>DATU Wallet</string>
  <key>CFBundleIdentifier</key><string>dev.datu.wallet</string>
  <key>CFBundleVersion</key><string>1.0.0</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>datu-wallet</string>
  <key>LSUIElement</key><true/>
  <key>LSBackgroundOnly</key><true/>
</dict>
</plist>
PLIST

cat > "$APP/Contents/MacOS/datu-wallet" << 'LAUNCHER'
#!/bin/sh
# Windowless wallet service: the key-holding bridge, loopback only.
# Data lives in ~/Library/Application Support/DATU (persistent, not /tmp).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../Resources/datu"
DATA_DIR="$HOME/Library/Application Support/DATU"
PORT="${DATU_WALLET_PORT:-7488}"
mkdir -p "$DATA_DIR"
exec "$BIN" --data-dir "$DATA_DIR" wallet serve --addr "127.0.0.1:$PORT"
LAUNCHER

chmod +x "$APP/Contents/MacOS/datu-wallet"
cp "$BIN" "$APP/Contents/Resources/datu"
chmod +x "$APP/Contents/Resources/datu"

echo "built: $APP"
echo "  service: datu wallet serve on 127.0.0.1:${DATU_WALLET_PORT:-7488} (port override: DATU_WALLET_PORT)"
echo "  data:    ~/Library/Application Support/DATU"
