# Prebuilt `vault_ffi` native libraries

Place `libvault_ffi.so` here per ABI after cross-compiling:

```
jniLibs/
  arm64-v8a/libvault_ffi.so
  armeabi-v7a/libvault_ffi.so
  x86_64/libvault_ffi.so
```

Build + copy from the repo root (requires Android NDK + Rust Android targets):

```powershell
.\scripts\build-vault-ffi.ps1 -Android -CopyToFlutter
```

Without these files the app still runs; Flutter falls back to the in-memory mock
store until native crypto is present.
