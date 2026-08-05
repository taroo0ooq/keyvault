# SQLCipher support (KI-001)

## Default (shipped CI / Windows MSVC)

| Layer | Mechanism |
|-------|-----------|
| File | Plain SQLite (`rusqlite` **bundled**) |
| Records | Field-level **AES-256-GCM** under Argon2id master key |
| Meta | `storage_backend=sqlite-aead` |

This is the **accepted interim** for portable CI without OpenSSL/SQLCipher native toolchains.

## Optional full-file SQLCipher

Build with:

```bash
cargo test -p vault-core --features sqlcipher
cargo build -p vault-daemon -p vault-ffi --features vault-core/sqlcipher --release
```

| Layer | Mechanism |
|-------|-----------|
| File | **SQLCipher** (`bundled-sqlcipher-vendored-openssl`) |
| Records | Same field-level AEAD (defense in depth) |
| Meta | `storage_backend=sqlcipher-aead` |
| Key | Master password applied as `PRAGMA key` on open/create |

### Compatibility

- SQLCipher and plain-SQLite vault **files are not interchangeable**.
- Existing plain vaults stay openable with default builds.
- Unlock path re-applies the SQLCipher key when the feature is enabled.

### Windows notes

- `bundled-sqlcipher-vendored-openssl` compiles OpenSSL from source (slow first build; needs a C toolchain).
- Prefer Linux/macOS CI matrix jobs for SQLCipher smoke if MSVC OpenSSL builds are flaky.

### Security posture

Even with SQLCipher enabled, KeyVault **keeps** per-field AEAD so UI/FFI never see plaintext columns and so export/backup formats stay consistent.

### Status

| Item | State |
|------|--------|
| Schema compatibility | Done |
| Feature flag + PRAGMA key | Done (this doc + `vault-core` feature `sqlcipher`) |
| Default CI uses SQLCipher | No (keeps `sqlite-aead`) |
| Optional Linux SQLCipher CI | Yes — `.github/workflows/sqlcipher.yml` (not in `required-gate`) |
| Formal KI-001 closure | **Reduced** — Ubuntu green path exists; Windows MSVC packaging still optional product decision |

### CI (optional, non-blocking)

Workflow: [`.github/workflows/sqlcipher.yml`](../.github/workflows/sqlcipher.yml)

| Trigger | Behavior |
|---------|----------|
| PR / push touching `vault-core` / this doc | Runs Ubuntu `cargo test -p vault-core --features sqlcipher` + daemon smoke |
| Weekly Monday 08:00 UTC | Canary so the path does not bit-rot |
| `workflow_dispatch` | Manual re-run |

**Not** part of primary `required-gate` — default merges stay on portable `sqlite-aead`.
