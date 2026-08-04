# vault-core

Zero-knowledge cryptographic core for KeyVault.

## Modules

| Module | Responsibility |
|--------|----------------|
| `kdf` | Argon2id master-key derivation |
| `vault_crypto` | AES-256-GCM / XChaCha20-Poly1305 envelopes |
| `password` | Generator (8–128) + entropy scoring |
| `secure_key` | DPAPI / software-dev key wrap |
| `vault_db` | SQLCipher-compatible schema + encrypted CRUD |

## Tests

```bash
cargo test -p vault-core
```
