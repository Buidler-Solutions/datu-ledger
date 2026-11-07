#!/bin/sh
# Install DATU Wallet.app for the current user and start it at login.
# Idempotent: re-running replaces the app and reloads the LaunchAgent.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/dist/DATU Wallet.app"
DEST="$HOME/Applications/DATU Wallet.app"
LABEL="dev.datu.wallet"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/datu-wallet.log"

if [ ! -d "$APP" ]; then
  echo "app not built - run packaging/macos/build.sh first" >&2
  exit 1
fi

mkdir -p "$HOME/Applications" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
rm -rf "$DEST"
cp -R "$APP" "$DEST"

cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DEST/Contents/MacOS/datu-wallet</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLISTEOF

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo "installed: $DEST"
echo "agent:     $PLIST (runs at login, restarts if stopped)"
echo "log:       $LOG"
echo
echo "the browser wallet extension pairs itself - open it and create an identity."
echo "check: curl -s http://127.0.0.1:7488/v1/pair -H 'Origin: chrome-extension://x' | head -c 80"
