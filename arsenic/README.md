# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V1** file encryption format (`.arsn`).

Used by the [`cryptyrust`](../cryptyrust) binary (GUI + CLI + key management) and the [`arsenic_ffi`](../ffi) C FFI layer.

---

## Features

- **Hybrid post-quantum asymmetric encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203). Each recipient gets an independent keyslot; files are secure against classical and quantum adversaries
- **Multiple passphrase keyslots** — up to 15 independent passwords on the same file; any of them can decrypt
- **Optional zstd compression** — compresses before encrypting (levels 1–22); with documented size-leak warning
- **ASCII armor** — base64 transport encoding for email and text channels; auto-detected on decrypt
- **Partial / random-access block decryption** — decrypt block N without reading blocks 0..N-1
- **Streaming to non-seekable output** — encrypt to stdout, sockets, or any `Write`
- **Three selectable AEAD ciphers** for header and payload independently:
  - `Deoxys-II-256` — beyond-birthday-bound security *(default header)*
  - `XChaCha20-Poly1305` — 192-bit nonce, software-friendly *(default payload)*
  - `AES-256-GCM-SIV` — nonce-misuse resistant
- **Argon2id** key derivation with two presets (`Interactive` 256 MiB / `Sensitive` 1 GiB)
- **LUKS-style keyslot** — password change rewrites only the 48-byte DEK wrapper; payload untouched
- **BLAKE3 Merkle tree** — domain-separated integrity over all encrypted blocks; verified before any plaintext write
- **Streaming block processing** — O(block_size + N_blocks × 32) memory regardless of file size
- **Crash-safe rekey** — `.bak` backup written and fsynced before any in-place write
- **Sender identity embedding** — public keys stored unencrypted in header (advisory)
- **Key material erasure** — `Secret<T>` wrappers zeroized on drop

---

## Quick start

```toml
[dependencies]
arsenic = { path = "../arsenic" }
```

### Symmetric encrypt / decrypt

```rust
use arsenic::{encrypt_arsenic, decrypt_arsenic, ArsenicParams, ArsenicStrength, Secret, Ui};
use std::io::Cursor;

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

let plaintext = b"hello world";
let password  = Secret::new("my passphrase".to_string());
let params    = ArsenicParams::from(ArsenicStrength::Interactive);

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());
encrypt_arsenic(&mut input, &mut output, &password, &NoUi, plaintext.len() as u64, &params)?;
let ciphertext = output.into_inner();

let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());
decrypt_arsenic(&mut input, &mut output, &password, &NoUi, ciphertext.len() as u64)?;
```

### ASCII armor

```rust
use arsenic::{armor, dearmor};

let ct = /* ... encrypt ... */;
let armored = armor(&ct);        // "-----BEGIN ARSENIC ENCRYPTED FILE-----\n..."
let back    = dearmor(&armored)?; // → original bytes
```

### Compression

```rust
let mut params = ArsenicParams::from(ArsenicStrength::Interactive);
params.compress = Some(3); // zstd level 3
// Warning: leaks plaintext entropy via ciphertext size — see COMPRESSION_LEAKS_SIZE
```

### Multiple passphrase slots

```rust
use arsenic::{arsenic_add_passphrase, arsenic_remove_passphrase, arsenic_list_passphrases};

arsenic_add_passphrase(path, &existing_pw, &new_pw, &NoUi)?;
arsenic_remove_passphrase(path, &primary_pw, &pw_to_remove, &NoUi)?;
let extra_count = arsenic_list_passphrases(path)?; // number of extra slots (0 = primary only)
```

### Partial / random-access block decryption

```rust
use arsenic::decrypt_block_at;

// Decrypt block 500 of a multi-block file without reading blocks 0–499.
// Note: only the block's AEAD tag is verified — no Merkle root check.
// Do not use for security-critical access control decisions.
let block = decrypt_block_at(&mut seekable_input, &password, 500, &NoUi)?;
```

---

## API overview

| Symbol | Description |
|---|---|
| `encrypt_arsenic` | Stream encrypt: `Read` → `Write + Seek` |
| `encrypt_arsenic_to_writer` | Stream encrypt to non-seekable `Write` (buffers ciphertext in RAM) |
| `decrypt_arsenic` | Stream decrypt with Merkle verification; `Read + Seek` → `Write` |
| `decrypt_arsenic_with_key` | Asymmetric stream decrypt with hybrid keypair |
| `decrypt_block_at` | Decrypt one block by index (AEAD only, no Merkle) |
| `decrypt_block_at_with_key` | Same, asymmetric path |
| `armor` | Encode binary ciphertext as ASCII armor |
| `dearmor` | Decode ASCII armor back to binary |
| `find_decrypting_key` | Probe header to find which keypair can open the file |
| `arsenic_main_routine` | File-level encrypt/decrypt |
| `arsenic_main_routine_with_key` | File-level asymmetric decrypt |
| `arsenic_rekey` | Crash-safe in-place password change |
| `arsenic_add_recipient` | Add a hybrid keyslot |
| `arsenic_remove_recipient` | Remove a keyslot by index |
| `arsenic_list_recipients` | List ephemeral X25519 keys of all keyslots |
| `arsenic_find_matching_key` | Find which stored key can decrypt a file |
| `arsenic_add_passphrase` | Add an extra passphrase slot |
| `arsenic_remove_passphrase` | Remove an extra passphrase slot |
| `arsenic_list_passphrases` | Count extra passphrase slots |
| `arsenic_read_sender_info` | Read sender identity from public header |
| `ArsenicParams` | Cipher IDs, Argon2id cost, recipients, compression, sender |
| `HybridRecipient` | Combined X25519 + ML-KEM-768 public key |
| `ArsenicStrength` | `Interactive` (256 MiB) / `Sensitive` (1 GiB) |
| `CipherId` | `DeoxysII256` · `XChaCha20Poly1305` · `Aes256GcmSiv` |
| `EnvelopeMetadata` | Filename, comment, timestamp from decrypted header |
| `SenderInfo` | Sender name + X25519 pk + ML-KEM-768 EK |
| `Secret<T>` | Zeroize-on-drop wrapper |
| `Ui` | Progress callback trait (0–100 %) |
| `ARMOR_LEAKS_SIZE` | Doc constant warning about armor size leakage |
| `COMPRESSION_LEAKS_SIZE` | Doc constant warning about compression size leakage |

---

## Cryptographic parameters

### Argon2id presets

| Preset | t | m (KB) | p | RAM | Time |
|---|---|---|---|---|---|
| `Interactive` *(default)* | 4 | 262 144 | 4 | 256 MiB | ~1–3 s |
| `Sensitive` | 12 | 1 048 576 | 4 | 1 GiB | ~10–30 s |

### Cipher IDs

| Byte | Algorithm | Default role |
|---|---|---|
| `0x02` | Deoxys-II-256 | Header |
| `0x03` | XChaCha20-Poly1305 | Payload |
| `0x04` | AES-256-GCM-SIV | — |

### Hybrid KEM

| Level | ML-KEM | EK size | CT size | Quantum security |
|---|---|---|---|---|
| **L768** *(default)* | ML-KEM-768 (NIST level 3) | 1184 B | 1088 B | ~180 bits |
| **L1024** | ML-KEM-1024 (NIST level 5) | 1568 B | 1568 B | ~256 bits |

### Multiple passphrase slots

- Max **15 extra slots** + 1 primary = 16 total
- All slots share the same Argon2id parameters (t/m/p)
- Primary slot: HeaderMAC fast-fail on wrong password
- Extra slots: AEAD-only authentication (full Argon2id cost per attempt)
- Extra slots are authenticated by the AEAD tag of `wrapped_dek`; they cannot be added or removed without the primary password

---

## Known design trade-offs

### No streaming decryption from non-seekable sources

`decrypt_arsenic` requires `R: Read + Seek`. The two-pass design (Pass 1: Merkle
verification; Pass 2: decrypt + write) guarantees no plaintext is written for
tampered or truncated files. Use `decrypt_block_at` for partial access with a
weaker guarantee (per-block AEAD only).

### Compression and plaintext size

`params.compress = Some(level)` buffers the entire input in RAM, compresses with
zstd, then encrypts. Memory usage is O(uncompressed_size + compressed_size).
Compressed files cannot use random-access decryption (`decrypt_block_at`).

### Recipient revocation

Removing a keyslot prevents future decryption of the modified file by that
recipient, but does not revoke access for anyone who already holds a copy with
their keyslot intact. True revocation requires re-encrypting with a new DEK.

---

## Format summary

```
┌──────────────────────────────────────────────┐  ← offset 0x00
│  Pre-MAC section    77 bytes                  │  HeaderMAC covers this
│  HeaderMAC          32 bytes                  │  BLAKE3_keyed_hash(KEK, pre-MAC)
│  Primary WrappedDEK 48 bytes                  │  AEAD(KEK, DEK)
│  extra_pass_count    4 bytes                  │  u32 LE (0..15)
│  Extra pass slots   76 bytes × K              │  AEAD(KEK_extra, DEK) each
│  hybrid_768_count    4 bytes                  │
│  Keyslots_768     1180 bytes × N              │  X25519+ML-KEM-768 wrapped DEK
│  hybrid_1024_count   4 bytes                  │
│  Keyslots_1024    1660 bytes × M              │  X25519+ML-KEM-1024 wrapped DEK
│  ProtectedMeta      ≥66 bytes                 │  AEAD(MetaKey, TLV[50+])
│  sender_present       1 byte                  │
│  [sender region]   ≥1219 bytes                │  plaintext, advisory
└──────────────────────────────────────────────┘  ← offset = header_total_size (≥236)
┌──────────────────────────────────────────────┐
│  Block 0: [compressed] plaintext + 16-byte AEAD tag  │
│  Block 1: …                                   │
└──────────────────────────────────────────────┘
  ↓ BLAKE3 Merkle tree (root stored in ProtectedMeta)
```

Full specification: [`FORMAT.md`](FORMAT.md).

---

## License

GPL-3.0-only — see [`LICENSE`](../LICENSE).
