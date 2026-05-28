# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V1** file encryption format (`.arsn`).

This crate is the core used by [`cryptyrust_cli`](../cli), the [`cryptyrust`](../gui) GUI, and the [`cryptyrust_ffi`](../ffi) C FFI layer.

---

## Features

- **Three selectable AEAD ciphers** — header cipher and payload cipher chosen independently:
  - `Deoxys-II-256` — tweakable-block-cipher AEAD *(default header cipher)*
  - `XChaCha20-Poly1305` — 192-bit nonce, software-friendly *(default payload cipher)*
  - `AES-256-GCM-SIV` — nonce-misuse resistant
- **Argon2id** key derivation with two presets (`Interactive` 256 MiB / `Sensitive` 1 GiB) plus a tiny pre-auth pass (~2 ms) to reject wrong passwords fast
- **LUKS-style keyslot** — password changes rewrite only the 48-byte DEK wrapper; the payload is never re-encrypted
- **BLAKE3 Merkle tree v1** — domain-separated integrity over all encrypted blocks; full-file verification before any plaintext is written
- **Full parallelism** via Rayon — every block is encrypted / decrypted independently
- **Optional per-block zstd compression** before encryption
- **Optional encrypted metadata** — filename, comment, timestamp stored inside the header
- **Key material erasure** — all sensitive values live in `Secret<T>` wrappers (zeroized on drop)
- **Crash-safe rekey** — `.bak` backup written and flushed before any in-place header write

For the complete binary format specification see [`FORMAT.md`](FORMAT.md).

---

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
arsenic = { path = "../arsenic" }   # or publish to crates.io and use a version
```

### Encrypt

```rust
use std::io::Cursor;
use arsenic::{encrypt_arsenic, ArsenicParams, ArsenicStrength, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

let plaintext = b"hello world";
let password  = Secret::new("my passphrase".to_string());
let params    = ArsenicParams::from(ArsenicStrength::Interactive);

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());

encrypt_arsenic(
    &mut input,
    &mut output,
    &password,
    &NoUi,          // or implement the Ui trait for progress reporting
    plaintext.len() as u64,
    &params,
)?;

let ciphertext = output.into_inner();
```

### Decrypt

```rust
use std::io::Cursor;
use arsenic::{decrypt_arsenic, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

let password = Secret::new("my passphrase".to_string());

let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());

let _meta = decrypt_arsenic(
    &mut input,
    &mut output,
    &password,
    &NoUi,
    ciphertext.len() as u64,
)?;

let plaintext = output.into_inner();
```

### File-level helpers

```rust
use std::path::Path;
use arsenic::{arsenic_main_routine, arsenic_rekey, Direction, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Encrypt a file → file.arsn
arsenic_main_routine(
    &Direction::Encrypt,
    Some("file.txt"),
    Some("file.txt.arsn"),
    &Secret::new("passphrase".to_string()),
    Box::new(NoUi),
    None,                    // use default ArsenicParams
)?;

// Change password in-place (only rewrites the 48-byte keyslot)
arsenic_rekey(
    Path::new("file.txt.arsn"),
    &Secret::new("old passphrase".to_string()),
    &Secret::new("new passphrase".to_string()),
    &NoUi,
)?;
```

---

## API overview

| Symbol | Description |
|---|---|
| `encrypt_arsenic` | Stream encrypt: `Read` → `Write` |
| `decrypt_arsenic` | Stream decrypt: `Read` → `Write`; returns `EnvelopeMetadata` |
| `arsenic_main_routine` | File-level encrypt / decrypt with automatic output path handling |
| `arsenic_rekey` | Crash-safe in-place password change |
| `ArsenicParams` | Cipher IDs, Argon2id cost, compression — full control over encryption parameters |
| `ArsenicStrength` | `Interactive` (256 MiB, ~1–3 s) / `Sensitive` (1 GiB, ~10–30 s) preset |
| `CipherId` | `DeoxysII256` · `XChaCha20Poly1305` · `Aes256GcmSiv` |
| `Compression` | `None` · `Zstd(level)` |
| `EnvelopeMetadata` | Filename, comment, timestamp, sizes recovered from the header on decrypt |
| `Secret<T>` | Zeroize-on-drop wrapper for sensitive values (passwords, keys) |
| `Ui` | Progress callback trait — implement to receive 0–100 % progress ticks |
| `bench_cipher_combinations` | Benchmark all three AEAD ciphers and rank by throughput |
| `is_arsenic_file` | Quick magic-byte check (`ARSN`) |
| `arsenic_read_params` | Read Argon2id parameters from a file header without decrypting |

---

## Cryptographic parameters

### Key derivation — Argon2id

| Preset | `t_cost` | `m_cost` (KB) | `p_cost` | RAM | Typical time |
|---|---|---|---|---|---|
| `Interactive` *(default)* | 4 | 262 144 | 4 | 256 MiB | ~1–3 s |
| `Sensitive` | 12 | 1 048 576 | 4 | 1 GiB | ~10–30 s |

Pre-authentication uses a tiny Argon2id pass (t=1, m=8 192 KB, p=1) to verify the header MAC before running the full KDF.

### Cipher IDs (as stored in the header)

| Byte | Algorithm | Default role |
|---|---|---|
| `0x02` | Deoxys-II-256 | Header cipher |
| `0x03` | XChaCha20-Poly1305 | Payload cipher |
| `0x04` | AES-256-GCM-SIV | — |

---

## Format summary

```
┌──────────────────────────────────────────┐  ← offset 0x00
│  Public section      76 bytes  (pre-MAC) │  plaintext, integrity-protected
│  HeaderMAC           32 bytes            │  HMAC-SHA256(PreKey, public section)
│  WrappedDEK          48 bytes            │  AEAD-encrypted 32-byte DEK (keyslot)
│  ProtectedMetadata  ≥76 bytes            │  AEAD-encrypted TLV metadata
└──────────────────────────────────────────┘  ← offset = header_total_size (≥ 232 bytes)
┌──────────────────────────────────────────┐
│  Block 0: ciphertext + 16-byte AEAD tag  │
│  Block 1: ciphertext + 16-byte AEAD tag  │
│  …                                       │
└──────────────────────────────────────────┘
     ↓
  BLAKE3 Merkle tree over all encrypted blocks
  root stored encrypted in ProtectedMetadata
```

Full specification: [`FORMAT.md`](FORMAT.md).

---

## License

GPL-3.0-only — see [`LICENSE`](../LICENSE).
