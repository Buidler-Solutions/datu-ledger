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

```bash
# host (macOS demo / tests)
cargo build -p datu-wallet-ffi          # -> target/debug/libdatu_wallet_ffi.dylib

# iOS staticlib (blake3 NEON asm needs deployment target >= 17.5)
rustup target add aarch64-apple-ios
IPHONEOS_DEPLOYMENT_TARGET=17.5 cargo build -p datu-wallet-ffi --target aarch64-apple-ios
# -> target/aarch64-apple-ios/debug/libdatu_wallet_ffi.a
# Xcode: add the .a to the Runner target, 'Headers' none, add -ldatu... nothing
# else needed; Dart resolves symbols via DynamicLibrary.process()

# Android .so (NDK at ~/Library/Android/sdk/ndk/28.2.13676358)
TC=$HOME/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin
CC_aarch64_linux_android=$TC/aarch64-linux-android24-clang \
AR_aarch64_linux_android=$TC/llvm-ar \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$TC/aarch64-linux-android24-clang \
  cargo build -p datu-wallet-ffi --target aarch64-linux-android
# -> target/aarch64-linux-android/debug/libdatu_wallet_ffi.so
# Gradle: drop it into android/app/src/main/jniLibs/arm64-v8a/
```

The Dart side is exercised end-to-end by `test/native_bridge_test.dart`
whenever the host dylib exists (`flutter test`).

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

## Mobile (phase 2 - implemented, integration pending)

The native core exists (`crates/wallet-ffi`, see above) and the Dart side is
done (`NativeWalletBridge`); what remains is wiring the artifacts into the
platform projects: add the `.a` to the Runner target in Xcode (iOS) and the
`.so` into `jniLibs/arm64-v8a/` (Android), then `flutter run -d <device>`.

## Screens

- **Home** - service status, identities (copy ed key)
- **Sign consent** - load/paste an envelope, pick identity + role, confirm with
  the passphrase, then copy or save the signed envelope
- **Ledger records** - read-only view of any node (`/v1/status`, `/v1/entries`);
  the wallet never needs to run a node itself
