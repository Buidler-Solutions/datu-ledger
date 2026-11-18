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

## How it signs (mobile / native core)

Phones cannot spawn sidecar processes, so the same Rust wallet code is linked
straight into the app as `crates/wallet-ffi` - a hand-rolled C ABI
(`datu_wallet_open` / `datu_wallet_request` / `datu_wallet_close` /
`datu_string_free`), JSON-in/JSON-out, mirroring the bridge routes and
response shapes (`identities`, `create`, `party-sign`, `seal`, `open`,
`export`, `import`, `sign-entry`, `verify-entry`; passphrase throttle: 5
wrong → 15 s lockout). No flutter_rust_bridge codegen - the surface is four
functions and a stable string contract.

`NativeWalletBridge` calls it via `dart:ffi`; each request runs
open → request → close on a background isolate, so Argon2id never freezes
the UI, and the Rust side runs the crypto on a dedicated 16 MB-stack thread
(debug ML-DSA keygen needs more stack than Dart isolate threads have).

Library resolution:

| Platform | How |
|---|---|
| iOS | `DynamicLibrary.process()` - the staticlib is linked into the app |
| Android | `DynamicLibrary.open('libdatu_wallet_ffi.so')` - bundled jniLib |
| macOS demo | `DATU_WALLET_FFI=/abs/path/libdatu_wallet_ffi.dylib` env var |

On mobile the native core is the only signer (no HTTP fallback); on desktop
it is used only when `DATU_WALLET_FFI` is set, otherwise the bridge process
serves as before. Home shows a **native core** chip when signing is in-process.

### Building the core

One script builds every slice and places the artifacts where the app
expects them (re-run it after any change to crates the wallet uses):

```bash
apps/wallet/tool/build_mobile_core.sh
# iOS      -> apps/wallet/ios/Frameworks/datu-wallet-ios-device.a
#             apps/wallet/ios/Frameworks/datu-wallet-ios-sim.a (x86_64 + arm64 sim)
# Android  -> apps/wallet/android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/
```

What it does, so you can do it by hand if needed:

- iOS: `cargo build -p datu-wallet-ffi --release --target
  aarch64-apple-ios` (device) and `aarch64-apple-ios-sim` +
  `x86_64-apple-ios` (simulator, merged with `lipo`). Both slices are arm64,
  so device and simulator stay as separate `.a` files.
- Linking is already wired in `ios/Flutter/Debug.xcconfig` and
  `Release.xcconfig` with `OTHER_LDFLAGS[sdk=iphoneos*]` /
  `[sdk=iphonesimulator*]` `-force_load`: every symbol is kept, so
  `DynamicLibrary.process()` resolves `datu_wallet_open` and friends. The
  Runner deployment target is 15.0 (Xcode 26+ refuses lower simulator
  targets).
- Android: builds each ABI with the NDK clang wrappers as `CC_<target>` +
  `AR_<target>` + `CARGO_TARGET_*_LINKER` (blake3 compiles NEON assembly,
  so the C toolchain must be set; `cargo ndk` does the same thing):
  `aarch64-linux-android` (API 24), `armv7-linux-androideabi`,
  `x86_64-linux-android`, copied into `jniLibs/<abi>/`.

Host (macOS demo / tests): `cargo build -p datu-wallet-ffi` ->
`target/debug/libdatu_wallet_ffi.dylib`.

The Dart side is exercised end-to-end by `test/native_bridge_test.dart`
(host dylib, `flutter test`) and by `integration_test/native_vault_test.dart`
on real devices: it creates an identity, signs an entry and verifies it with
the core compiled into the app:

```bash
flutter test integration_test -d <ios-simulator|android-device-id>
```

### End-to-end native demo on macOS

```bash
cargo build -p datu-wallet-ffi
cd apps/wallet && flutter run -d macos --dart-define=...   # or:
DATU_WALLET_FFI=$PWD/../../target/debug/libdatu_wallet_ffi.dylib flutter run -d macos
```

The Home card then reads *Native wallet core · in-process Rust* and signs
with the same keystore as the bridge (`~/Library/Application Support/DATU`).

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

## Mobile (standalone, no desktop)

Implemented and validated on-device (iOS Simulator + Android emulator,
integration test green on both): the app compiles the Rust wallet core into
the binary, so it creates identities, signs, seals and verifies with **no
desktop, no bridge process and no network**. Builds:

```bash
apps/wallet/tool/build_mobile_core.sh    # once, after core changes
cd apps/wallet
flutter build apk --debug                # -> build/app/outputs/flutter-apk/
flutter build ios --simulator --debug    # no signing team needed
flutter run -d <device>                  # on a phone or emulator
```

Notes: `adb install` needs a device with free `/data` (a full emulator leaves
386 MB and fails with "not enough space"); the iOS integration test runs the
crypto in `Runner.debug.dylib` (Xcode 26+ debug-dylib layout), which is where
the wallet symbols live. Display name on both platforms is DATU Signet.

The dApp channel (phones have no browser extension) is the next milestone:
in-app webview provider plus universal-link signing, wire-compatible with the
extension's action grammar and `datu-provider-v1` proof.

## Screens

- **Home** - service status, identities (copy ed key)
- **Sign consent** - load/paste an envelope, pick identity + role, confirm with
  the passphrase, then copy or save the signed envelope
- **Ledger records** - read-only view of any node (`/v1/status`, `/v1/entries`);
  the wallet never needs to run a node itself

## Standalone login (SignetAuth without a desktop)

The phone app is a complete signer on its own: the Rust wallet core is linked
into the app (`crates/wallet-ffi`), so signing needs no desktop, no bridge
process and no pairing token. That matters most for login, where a dApp lives
in a browser that must never hold keys.

Protocol (`datu-auth-v1`, same assertion format as extension sign-in):

1. The dApp creates a challenge (`newChallenge()` in `@greenarmor/datu-client`:
   `rp_id`, `origin`, 32-hex `nonce`, `expires_at_ms`) and shows it as a link:

       datu-auth://sign?rp_id=<rp>&origin=<origin>&nonce=<hex32>&expires_at_ms=<ms>&redirect=<https url>

   (The web form `https://<rp>/datu-auth?…` with the same parameters works for
   QR codes that must open a browser first.)

2. The phone receives the link (deep link, paste, or the in-app **Scan a QR
   code** camera view), reviews **who**
   is asking (rp_id and origin are shown next to the exact canonical bytes the
   signature will cover), unlocks the identity with the passphrase, and signs
   in the embedded core. The intent filter for `datu-auth://sign` lives in
   `android/app/src/main/AndroidManifest.xml`; the parser rejects foreign
   schemes, malformed nonces, non-http(s) origins, and expiries further than
   five minutes out.

3. The app returns
   `redirect#datu-assertion=<base64url(assertion JSON)>`. The assertion is
   `{domain, rp_id, origin, nonce, expires_at_ms, pubkey, signature}` and the
   dApp verifies it with `verifyAssertion()` (WebCrypto, no server call),
   matching the challenge it issued and refusing expired ones.

Try it without a phone: `flutter test test/datu_auth_test.dart` covers the
parser, canonical bytes and return URL. On a device: Settings documents the
data dir; the Login tab has a sample link button for a dry run.

Safety properties: the fragment never reaches a server (no referrer, no logs),
the nonce is single use and short lived, and a copied link is worthless
without a signature made while the challenge was live. The app refuses links
whose expiry is more than five minutes out so a link cannot be stockpiled.
