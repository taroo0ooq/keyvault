# KeyVault Mobile (Flutter)

Cross-platform mobile UI for KeyVault (iOS / Android).

## Status (Phase 2)

- Auth gate (create / unlock), vault list, CRUD, search, generate, copy
- **Native crypto** via `crates/vault-ffi` C ABI + `dart:ffi` (`lib/services/vault_ffi.dart`)
- **Biometric gate** (`local_auth`) before OS-enclave quick unlock
- Falls back to in-memory mock if `vault_ffi` dylib is not found (unit tests / UI-only)
- CI: `.github/workflows/vault-ffi.yml` builds Android jniLibs artifacts

## Build native library

From repo root:

```bash
cargo build -p vault-ffi --release
# Windows: target/release/vault_ffi.dll
```

Point Flutter at it:

```bash
# PowerShell
$env:VAULT_FFI_PATH = "$PWD\target\release\vault_ffi.dll"
cd apps/mobile
flutter run -d windows
```

## Run

```bash
cd apps/mobile
flutter pub get
flutter run
```

## Analyze

```bash
flutter analyze
flutter test
```
