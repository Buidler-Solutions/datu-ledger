#!/bin/sh
# Remove DATU Wallet.app and its login agent. Data in
# ~/Library/Application Support/DATU is kept - delete it yourself if you mean it.
set -eu

LABEL="dev.datu.wallet"
DEST="$HOME/Applications/DATU Wallet.app"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
rm -rf "$DEST"

echo "removed: $DEST"
echo "removed: $PLIST"
echo "kept:    ~/Library/Application Support/DATU (wallet data)"
echo "log:     ~/Library/Logs/datu-wallet.log"
