> [Version française](README_fr.md)

# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V1** file encryption format (`.arsn`).

Used by the [`cryptyrust`](../cryptyrust) binary (GUI + CLI + key management) and the [`arsenic_ffi`](../ffi) C FFI layer.

---

## Features

- **Hybrid post-quantum asymmetric encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203). Each recipient gets an independent keyslot; files stay decryptable by quantum computers *and* classical ones
- **Optional ML-DSA-65 signatures** (NIST FIPS 204) — files can be signed during encryption; signature verified automatically on decryption
- **Sender identity embedding** — the sender's public keys and display name can be stored unencrypted in the header. When the file is signed, the sender region is cryptographically authenticated (covered by the ML-DSA-65 signature); the recipient reads it without decrypting and can auto-add the sender as a trusted contact
- **Three selectable AEAD ciphers**, independently configurable for header and payload:
  - `Deoxys-II-256` — tweakable block cipher AEAD *(default header cipher)*
  - `XChaCha20-Poly1305` — 192-bit nonce, software-friendly *(default payload cipher)*
  - `AES-256-GCM-SIV` — nonce-misuse resistant
- **Argon2id** key derivation with two presets (`Interactive` 256 MiB / `Sensitive` 1 GiB). HeaderMAC keyed on the full KEK — every password attempt costs the full KDF, no faster oracle
- **LUKS-style keyslot** — password changes rewrite only the 48-byte DEK wrapper; the payload is never re-encrypted
- **BLAKE3 Merkle tree** — domain-separated integrity over all encrypted blocks; full-file verification before any plaintext is written
- **Streaming block processing** — O(block_size + N_blocks × 32) memory regardless of file size; files of any size processed correctly
- **Crash-safe rekey** — `.bak` backup written and fsynced (including parent-directory entry) before any in-place header write
- **Shared keystore** — X25519 + ML-KEM + ML-DSA-65 keys stored together in `{config}/cryptyrust/keys/` and shared by the GUI and CLI
- **Key material erasure** — all sensitive values in `Secret<T>` wrappers (zeroized on drop)

For the complete binary format specification see [`FORMAT.md`](FORMAT.md).

---

## Quick start

```toml
[dependencies]
arsenic = { path = "../arsenic" }
```

### Symmetric encrypt / decrypt

```rust
use std::io::Cursor;
use arsenic::{encrypt_arsenic, decrypt_arsenic, ArsenicParams, ArsenicStrength, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Encrypt
let plaintext = b"hello world";
let password  = Secret::new("my passphrase".to_string());
let params    = ArsenicParams::from(ArsenicStrength::Interactive);

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());
encrypt_arsenic(&mut input, &mut output, &password, &NoUi, plaintext.len() as u64, &params)?;
let ciphertext = output.into_inner();

// Decrypt
let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());
decrypt_arsenic(&mut input, &mut output, &password, &NoUi, ciphertext.len() as u64)?;
let plaintext_back = output.into_inner();
```

### Asymmetric (hybrid post-quantum) encrypt / decrypt

```rust
use arsenic::{
    encrypt_arsenic, decrypt_arsenic_with_key,
    ArsenicParams, ArsenicStrength, HybridRecipient,
    hybrid_recipient_from_privkey, Secret, Ui,
};
use std::io::Cursor;

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Recipient generates their keypair (once, stored in .key file)
let privkey: [u8; 32] = arsenic::random_bytes_32();
let recipient: HybridRecipient = hybrid_recipient_from_privkey(&privkey);

// Sender encrypts for the recipient (no password needed)
let plaintext = b"secret message";
let r = arsenic::random_bytes_32();
let random_kek: String = r.iter().map(|b| format!("{b:02x}")).collect();
let mut params = ArsenicParams::from(ArsenicStrength::Interactive);
params.recipients = vec![recipient];

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());
encrypt_arsenic(
    &mut input, &mut output,
    &Secret::new(random_kek), &NoUi,
    plaintext.len() as u64, &params,
)?;
let ciphertext = output.into_inner();

// Recipient decrypts with their private key
let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());
decrypt_arsenic_with_key(
    &mut input, &mut output,
    &Secret::new(privkey), &NoUi,
    ciphertext.len() as u64,
)?;
```

### File-level helpers

```rust
use std::path::Path;
use arsenic::{arsenic_main_routine, arsenic_rekey, Direction, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Encrypt file → file.arsn
arsenic_main_routine(
    &Direction::Encrypt, Some("file.txt"), Some("file.txt.arsn"),
    &Secret::new("passphrase".to_string()), Box::new(NoUi), None,
)?;

// Change password (only rewrites the 48-byte keyslot — instant on any file size)
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
| `encrypt_arsenic` | Stream encrypt: `Read` → `Write + Seek` |
| `decrypt_arsenic` | Stream decrypt: `Read + Seek` → `Write`; two-pass (verify Merkle, then write) |
| `decrypt_arsenic_with_key` | Asymmetric stream decrypt with X25519 private key |
| `find_decrypting_key` | Probe header to find which private key can open a file |
| `arsenic_main_routine` | File-level encrypt/decrypt |
| `arsenic_main_routine_with_key` | File-level asymmetric decrypt |
| `arsenic_rekey` | Crash-safe in-place password change |
| `arsenic_add_recipient` | Add a hybrid keyslot to an existing file |
| `arsenic_remove_recipient` | Remove a keyslot by index |
| `arsenic_list_recipients` | List ephemeral X25519 keys of all keyslots |
| `arsenic_find_matching_key` | Find which stored key can decrypt a file |
| `arsenic_check_signature` | Check ML-DSA-65 signature against contact trust store |
| `arsenic_read_verifying_key` | Read ML-DSA-65 verifying key without decrypting |
| `arsenic_read_sender_info` | Read sender identity from public header (no decryption) |
| `ArsenicParams` | Cipher IDs, Argon2id cost, recipients, signing, sender |
| `HybridRecipient` | Combined X25519 + ML-KEM-768 public key |
| `hybrid_recipient_from_privkey` | Build a `HybridRecipient` from a private key |
| `hybrid_encapsulation_key` | Derive ML-KEM EK from X25519 private key |
| `ArsenicStrength` | `Interactive` (256 MiB) / `Sensitive` (1 GiB) |
| `CipherId` | `DeoxysII256` · `XChaCha20Poly1305` · `Aes256GcmSiv` |
| `EnvelopeMetadata` | Filename, comment, timestamp from decrypted header |
| `SenderInfo` | Sender name + X25519 pk + ML-KEM-768 EK (from public header) |
| `SignatureStatus` | `NotSigned` · `SignedByKnown(name)` · `SignedByUnknown` · `Invalid` |
| `Secret<T>` | Zeroize-on-drop wrapper |
| `Ui` | Progress callback trait (0–100 %) |
| `bench_cipher_combinations` | Benchmark all ciphers, rank by throughput |
| `keystore::load_keystore` | Load hybrid keypairs from `{config}/cryptyrust/keys/` |
| `keystore::load_contacts` | Load contacts (hybrid public keys) |
| `keystore::resolve_recipient` | Resolve name/path → `HybridRecipient` |
| `encode_pubkey` / `decode_pubkey` | X25519 key bech32 encoding (`arsenic1…`) |
| `encode_mlkem_pubkey` / `decode_mlkem_pubkey` | ML-KEM EK bech32 encoding (`arsenic1m…`) |
| `encode_privkey` / `decode_privkey` | Private key bech32 encoding (`ARSENIC-SECRET-KEY-1…`) |

---

## Cryptographic parameters

### Argon2id presets

| Preset | t | m (KB) | p | RAM | Time |
|---|---|---|---|---|---|
| `Interactive` *(default)* | 4 | 262 144 | 4 | 256 MiB | ~1–3 s |
| `Sensitive` | 12 | 1 048 576 | 4 | 1 GiB | ~10–30 s |

The HeaderMAC is keyed with the full KEK, so every password attempt costs the full Argon2id derivation. There is no cheaper pre-authentication oracle.

### Cipher IDs (header byte)

| Byte | Algorithm | Default role |
|---|---|---|
| `0x02` | Deoxys-II-256 | Header cipher |
| `0x03` | XChaCha20-Poly1305 | Payload cipher |
| `0x04` | AES-256-GCM-SIV | — |

### Hybrid KEM

Two security levels are supported, selected per-file at encryption time:

| Level | ML-KEM variant | EK size | CT size | Quantum security |
|---|---|---|---|---|
| **L768** *(default)* | ML-KEM-768 (NIST level 3) | 1184 B | 1088 B | ~180 bits |
| **L1024** | ML-KEM-1024 (NIST level 5) | 1568 B | 1568 B | ~256 bits |

X25519 + ML-KEM are combined via BLAKE3 hybrid KEM binding — the hybrid is secure if either component holds.

**Independent entropy:** since v1.5.0, the X25519, ML-KEM, and ML-DSA-65 seeds are generated **independently** from the OS CSPRNG. The `.key` file stores a 32-byte X25519 seed, a separate 64-byte ML-KEM seed (`d||z`), and a 32-byte ML-DSA-65 signing seed. Old key files that only stored 32 bytes derive the ML-KEM seed via BLAKE3 (backward compat).

### ML-DSA-65 signatures

Files can optionally be signed with an ML-DSA-65 key (NIST FIPS 204, ~192-bit quantum security).

**Signed message:**
```
pre_mac[77] || sender_bytes   — when sender identity is embedded
pre_mac[77]                   — no sender (backward compatible with v1.5.x)
```

Covering the sender region in the signed message prevents key-substitution attacks: an attacker who intercepts the file cannot silently replace the sender's public keys without invalidating the signature.

Verification is automatic and mandatory on decryption — both in `decrypt_arsenic` (symmetric path) and `decrypt_arsenic_with_key` (asymmetric path). A signature mismatch is always a hard error.

**GUI:** the signing key is embedded in each encryption keypair (`.key` file, generated with `⚡ Generate`). Select the signing identity in Config → Signing key. Files received with an unsigned sender region display an orange ⚠ warning.

**CLI:** use a separate `.sigkey` file generated with `cryptyrust keygen --sign`. Pass `-S alice` to sign during encryption.

---

## Known design trade-offs

These are acknowledged limitations, not bugs. They match the behaviour of
comparable tools (LUKS 2, age, Sequoia).

### No streaming decryption from non-seekable sources

`decrypt_arsenic` and `decrypt_arsenic_with_key` require `R: Read + Seek`.
Decryption from stdin, network sockets, or pipes is not supported.

**Why:** the two-pass design is intentional. Pass 1 reads all encrypted
blocks and verifies the BLAKE3 Merkle root stored in `ProtectedMetadata`.
Only if the root matches does Pass 2 decrypt and write plaintext.
This guarantees that **no plaintext byte is ever written for a tampered,
truncated, or corrupted file**.

An AEAD-on-the-fly (single-pass) alternative would authenticate each block
individually (AEAD tag + block-index AAD prevents reordering), but it cannot
prevent a truncation attack: an adversary who silently drops the last N
complete blocks causes N × block_size bytes of plaintext to be emitted before
the decryptor notices the shortfall against `OriginalSize`. The two-pass
Merkle approach closes this gap at near-zero memory cost
(N_blocks × 32 bytes ≈ 20 KiB for a 10 GiB file) and low I/O cost (Pass 1
is pure BLAKE3 hashing; the second read is served from OS cache on local
files).

A future `--stream` mode offering AEAD-on-the-fly with an explicit
opt-in warning (weaker guarantee accepted) would make pipe-based workflows
possible. This is tracked as a known limitation, not a security flaw.

### Plaintext metadata

The following fields are readable by any party in possession of the file:

- **`hybrid_count` and `header_total_size`** — reveal the exact number of
  asymmetric recipients. Hiding this without a fixed-size header or
  trial-decryption strategy would require a fundamental format redesign.
- **`t_cost` / `m_cost` / `p_cost`** — KDF parameters must be in plaintext
  because they are required to derive the KEK before any decryption can
  occur. There is no practical alternative given the format's constraints.
- **Sender region** — the sender's display name and public keys are plaintext
  by design. This is required for the dead-drop model where the recipient
  must identify the sender without an authenticated channel.

These fields are covered by the HeaderMAC and cannot be silently tampered
with, but their values are always observable.

### Recipient revocation

`arsenic_remove_recipient(path, password, index)` removes a keyslot in
O(header\_size) — the payload is streamed unchanged and the DEK is not
rotated. This is sufficient to prevent future decryption of the **modified**
file by the removed party.

**Cryptographic limit:** removing a keyslot does not revoke access for a
recipient who already holds a copy of the file with their keyslot intact.
The DEK is unchanged; anyone who has decapsulated it can still decrypt any
copy they possess. True revocation (guaranteeing a past recipient loses
access) always requires re-encrypting the payload with a new DEK.
This is a fundamental property of any multi-recipient symmetric encryption
scheme — LUKS, age, and Sequoia share the same constraint.

### X25519, ML-KEM, and ML-DSA-65 entropy

Since v1.5.0, all three key components are generated **independently** from
the OS CSPRNG (`getrandom`). Each `.key` file stores:
- A 32-byte X25519 private key seed
- A separate 64-byte ML-KEM seed (`d[32] || z[32]`) in a `# mlkem-seed:` line
- A separate 32-byte ML-DSA-65 signing seed in a `# sign-seed:` line

This eliminates any shared root of trust among the three components. A
weakness in one cannot compromise the others.

Legacy key files (without `# mlkem-seed:`) still derive the ML-KEM seed via
BLAKE3 for backward compatibility.

---

## Format summary

```
┌──────────────────────────────────────────────┐  ← offset 0x00
│  Pre-MAC section    77 bytes  (pre-MAC)       │  plaintext, integrity-protected
│  HeaderMAC          32 bytes                  │  BLAKE3_keyed_hash(KEK, pre-MAC)
│  WrappedDEK         48 bytes                  │  AEAD-encrypted DEK (symmetric keyslot)
│  hybrid_768_count    4 bytes                  │  number of ML-KEM-768 keyslots
│  Keyslot_768_0    1180 bytes  ┐               │  X25519+ML-KEM-768 wrapped DEK × N
│  hybrid_1024_count   4 bytes  │               │  number of ML-KEM-1024 keyslots
│  Keyslot_1024_0   1660 bytes  │               │  X25519+ML-KEM-1024 wrapped DEK × M
│  ProtectedMeta     ≥66 bytes  │               │  AEAD-encrypted TLV (Merkle root, size…)
│  sig_present          1 byte  │               │  0x00=none / 0x01=ML-DSA-65
│  [verif_key+sig   5261 bytes] ┘               │  ML-DSA-65 verifying key + signature
│  sender_present       1 byte                  │  0x00=none / 0x01=sender present
│  [name+len+x25519+mlkem_ek]                   │  Plaintext sender identity (≥1219 bytes)
└──────────────────────────────────────────────┘  ← offset = header_total_size (≥233 bytes)
┌──────────────────────────────────────────────┐
│  Block 0: ciphertext + 16-byte AEAD tag       │
│  Block 1: ciphertext + 16-byte AEAD tag       │  blocks processed sequentially,
│  …                                            │  parallel file-level processing in GUI
└──────────────────────────────────────────────┘
  ↓ BLAKE3 Merkle tree over all encrypted blocks (root stored in ProtectedMeta)
```

Full specification: [`FORMAT.md`](FORMAT.md).

---

## License

GPL-3.0-only — see [`LICENSE`](../LICENSE).
