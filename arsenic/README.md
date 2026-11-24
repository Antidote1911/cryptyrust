# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V2** file encryption format (`.arsn`).

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
- **LUKS-style keyslots** — a password change rewrites only its 92-byte slot and the header MAC; payload untouched
- **Authenticated header** — a BLAKE3 MAC keyed from the file key covers every header byte, for password and keypair holders alike
- **Truncation-proof payload** — block index and a final-block flag are bound into every block; single-pass decryption
- **Parallel streaming** — blocks are processed in parallel within a bounded window (≤ 128 MiB of plaintext), with or without compression
- **Crash-safe rekey** — `.bak` backup written and fsynced before any in-place write
- **Sender identity embedding** — public keys stored in clear in the header, covered by the header MAC (a claim, not a proof of identity)
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
arsenic_remove_passphrase(path, &any_pw_of_the_file, &pw_to_remove, &NoUi)?;
let count = arsenic_list_passphrases(path)?; // number of passwords (0 = keypairs only)
```

### Partial / random-access block decryption

```rust
use arsenic::decrypt_block_at;

// Decrypt block 500 of a multi-block file without reading blocks 0–499.
// The header and that block are authenticated; the rest of the file is not read.
let block = decrypt_block_at(&mut seekable_input, &password, 500, &NoUi)?;
```

---

## API overview

| Symbol | Description |
|---|---|
| `encrypt_arsenic` | Stream encrypt: `Read` → `Write + Seek` |
| `encrypt_arsenic_to_writer` | Stream encrypt to non-seekable `Write` (buffers ciphertext in RAM) |
| `decrypt_arsenic` | Single-pass authenticated decrypt; `Read + Seek` → `Write` |
| `decrypt_arsenic_with_key` | Asymmetric stream decrypt with hybrid keypair |
| `decrypt_block_at` | Decrypt one block by index (header + that block authenticated) |
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
| `arsenic_add_passphrase` | Add a password |
| `arsenic_remove_passphrase` | Remove a password |
| `arsenic_list_passphrases` | Count the passwords of a file |
| `arsenic_read_sender_info` | Read sender identity from the header (authenticated only by a decryption) |
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

- Up to **16 passwords** per file, all equal: any of them opens the file and can add, change or remove another
- All slots share the Argon2id salt and parameters, so a wrong password costs one Argon2id run whatever their number
- Each slot carries a check tag: the matching slot is found in constant time, and the slot is committed to its key
- A file encrypted for recipients only has **no** password slot
- The last key slot of a file cannot be removed

---

## Known design trade-offs

### Plaintext is released block by block

`decrypt_arsenic` is a single pass: each window of blocks is authenticated,
then written. A truncated or tampered file is always detected, but possibly
after earlier (authentic) plaintext was written — the caller must discard the
output when an error is returned. The file-level functions do this.

It requires `R: Read + Seek`, because the position of the last block is taken
from the file length.

### Compression and plaintext size

`params.compress = Some(level)` streams the input through zstd before
encryption; memory stays bounded. Compression leaks information about the
plaintext through the ciphertext size. Compressed files cannot use
random-access decryption (`decrypt_block_at`).

### Changing a password does not change the file key

A password change or removal rewrites key slots only. Anyone who knew the old
password and kept a copy of the old file can still decrypt that copy.

### Recipient revocation

Removing a keyslot prevents future decryption of the modified file by that
recipient, but does not revoke access for anyone who already holds a copy with
their keyslot intact. True revocation requires re-encrypting with a new DEK.

---

## Format summary

```
┌──────────────────────────────────────────────┐  offset 0
│  Public parameters   65 bytes                 │  ciphers, Argon2id salt and costs, base nonce
│  Password slots       4 + 92 × K              │  K = 0…16, AEAD(wrap key, DEK) + check tag
│  Keyslots 768         4 + 1180 × N            │  X25519 + ML-KEM-768 wrapped DEK
│  Keyslots 1024        4 + 1660 × M            │  X25519 + ML-KEM-1024 wrapped DEK
│  Protected metadata   4 + nonce + AEAD(TLV)   │  size, block size, compression, filename…
│  Sender               1 byte [+ identity]     │  in clear
│  HeaderMAC           32 bytes                 │  BLAKE3 keyed from the DEK, over all of the above
└──────────────────────────────────────────────┘  offset = header_total_size (≥ 155)
┌──────────────────────────────────────────────┐
│  Block 0: plaintext + 16-byte AEAD tag        │  index + final flag in nonce and AAD
│  Block 1: …                                   │  at least one block, the last one is "final"
└──────────────────────────────────────────────┘
```

Full specification: [`FORMAT.md`](FORMAT.md).

---

## License

GPL-3.0-only — see [`LICENSE`](../LICENSE).
