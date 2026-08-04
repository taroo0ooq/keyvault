#!/usr/bin/env bash
# Cross-build vault_ffi for Android ABIs into Flutter jniLibs.
# Requires: Rust, cargo-ndk, ANDROID_NDK_HOME
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  echo "ANDROID_NDK_HOME is not set" >&2
  exit 1
fi

rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked 2>/dev/null || true

OUT="apps/mobile/android/app/src/main/jniLibs"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o "$OUT" \
  build -p vault-ffi --release

echo "Wrote libraries under $OUT"
find "$OUT" -type f -name '*.so'
