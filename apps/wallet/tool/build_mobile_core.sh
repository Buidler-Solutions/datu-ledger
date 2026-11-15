#!/bin/sh
# Build the DATU wallet core (crates/wallet-ffi) for mobile and place the
# artifacts where the Flutter app expects them:
#   iOS      apps/wallet/ios/Frameworks/datu-wallet-ios-{device,sim}.a
#   Android  apps/wallet/android/app/src/main/jniLibs/<abi>/libdatu_wallet_ffi.so
#
# The phone cannot spawn the desktop bridge, so the Rust core is compiled
# into the app and loaded in-process (Diego: Dart FFI). Re-run this after
# changing any crate the wallet depends on.
#
#   apps/wallet/tool/build_mobile_core.sh
set -eu

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"
BIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
APP=apps/wallet

cd "$ROOT"
cargo build -p datu-wallet-ffi --release --target aarch64-apple-ios
cargo build -p datu-wallet-ffi --release --target aarch64-apple-ios-sim
cargo build -p datu-wallet-ffi --release --target x86_64-apple-ios

mkdir -p "$APP/ios/Frameworks"
cp target/aarch64-apple-ios/release/libdatu_wallet_ffi.a "$APP/ios/Frameworks/datu-wallet-ios-device.a"
lipo -create \
  target/aarch64-apple-ios-sim/release/libdatu_wallet_ffi.a \
  target/x86_64-apple-ios/release/libdatu_wallet_ffi.a \
  -output "$APP/ios/Frameworks/datu-wallet-ios-sim.a"

for abi_triple in "arm64-v8a:aarch64-linux-android" "armeabi-v7a:armv7-linux-androideabi" "x86_64:x86_64-linux-android"; do
  abi="${abi_triple%%:*}"
  triple="${abi_triple#*:}"
  case "$triple" in
    aarch64-linux-android)
      cc="$BIN/aarch64-linux-android24-clang" ;;
    armv7-linux-androideabi)
      cc="$BIN/armv7a-linux-androideabi24-clang" ;;
    x86_64-linux-android)
      cc="$BIN/x86_64-linux-android24-clang" ;;
  esac
  env_var="$(echo "$triple" | tr '-' '_')"
  env "CC_$env_var=$cc" "AR_$env_var=$BIN/llvm-ar" \
    "CARGO_TARGET_$(echo "$triple" | tr '[:lower:]-' '[:upper:]_')_LINKER=$cc" \
    cargo build -p datu-wallet-ffi --release --target "$triple"
  mkdir -p "$APP/android/app/src/main/jniLibs/$abi"
  cp "target/$triple/release/libdatu_wallet_ffi.so" \
    "$APP/android/app/src/main/jniLibs/$abi/libdatu_wallet_ffi.so"
done

echo "mobile wallet core built: iOS (device+sim) and Android (arm64, armv7, x86_64)"
