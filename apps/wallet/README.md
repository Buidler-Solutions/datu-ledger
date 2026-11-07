# DATU Wallet (Flutter)

Desktop + mobile wallet UI for DATU. Same idea as the browser extension, but as
a native app - no browser required.

## How it signs (desktop)

The app ships the `datu` binary inside its bundle and runs `datu wallet serve`
as a private, loopback-only service (port 7488). It reuses an already-running
service when one exists (e.g. the `DATU Wallet.app` LaunchAgent from
`packaging/macos/`), otherwise it starts one with its own data dir:

| Platform | Data dir |
|---|---|
| macOS | `~/Library/Application Support/DATU` |
| Linux | `~/.local/share/datu` |
| Windows | `%APPDATA%\DATU` |

Keys never enter the Flutter process; every signature is a bridge request that
needs the identity passphrase.

## Run

```bash
cd apps/wallet
flutter pub get
flutter run -d macos                  # or -d chrome / -d <device>
```

Bundle the bridge into the built app:

```bash
flutter build macos --debug
tool/bundle_bridge.sh                 # copies target/debug/datu into Resources/
```

If no bundled binary is found the app falls back to `DATU_BIN` or `datu` on
`PATH`, and the error screen accepts a manual bridge URL + pairing token (handy
for the demo bridges on 7482/7483).

## Mobile (phase 2)

iOS/Android cannot spawn sidecar processes, so mobile builds will embed the Rust
wallet core directly via `flutter_rust_bridge` (a `datu-wallet-ffi` crate
exposing unlock / party-sign / seal / open / sign-entry). The screens already
talk only to `WalletBridge`, so the swap is confined to
`lib/core/bridge/`.

## Screens

- **Home** - service status, identities (copy ed key)
- **Sign consent** - load/paste an envelope, pick identity + role, confirm with
  the passphrase, then copy or save the signed envelope
- **Ledger records** - read-only view of any node (`/v1/status`, `/v1/entries`);
  the wallet never needs to run a node itself
