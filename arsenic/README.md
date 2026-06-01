> [Version française](README_fr.md)

# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V1** file encryption format (`.arsn`).

Used by the [`cryptyrust`](../cryptyrust) binary (GUI + CLI + key management) and the [`arsenic_ffi`](../ffi) C FFI layer.

---

## Features

- **Hybrid post-quantum asymmetric encryption** — X25519 + ML-KEM-768 (NIST FIPS 203). Each recipient gets an independent keyslot; files stay decryptable by quantum computers *and* classical ones
- **Three selectable AEAD ciphers**, independently configurable for header and payload:
  - `Deoxys-II-256` — tweakable block cipher AEAD *(default header cipher)*
  - `XChaCha20-Poly1305` — 192-bit nonce, software-friendly *(default payload cipher)*
  - `AES-256-GCM-SIV` — nonce-misuse resistant
- **Argon2id** key derivation with two presets (`Interactive` 256 MiB / `Sensitive` 1 GiB). HeaderMAC keyed on the full KEK — every password attempt costs the full KDF, no faster oracle
- **LUKS-style keyslot** — password changes rewrite only the 48-byte DEK wrapper; the payload is never re-encrypted
- **BLAKE3 Merkle tree** — domain-separated integrity over all encrypted blocks; full-file verification before any plaintext is written
- **Streaming block processing** — O(block_size + N_blocks × 32) memory regardless of file size; files of any size processed correctly
- **Crash-safe rekey** — `.bak` backup written and fsynced (including parent-directory entry) before any in-place header write
- **Shared keystore** — X25519 + ML-KEM keypairs stored in `{config}/cryptyrust/keys/` and shared by the GUI, CLI, and keygen tool
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
| `ArsenicParams` | Cipher IDs, Argon2id cost, recipients |
| `HybridRecipient` | Combined X25519 + ML-KEM-768 public key |
| `hybrid_recipient_from_privkey` | Build a `HybridRecipient` from a private key |
| `hybrid_encapsulation_key` | Derive ML-KEM EK from X25519 private key |
| `ArsenicStrength` | `Interactive` (256 MiB) / `Sensitive` (1 GiB) |
| `CipherId` | `DeoxysII256` · `XChaCha20Poly1305` · `Aes256GcmSiv` |
| `EnvelopeMetadata` | Filename, comment, timestamp from decrypted header |
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

| Component | Algorithm | Key size | Security |
|---|---|---|---|
| Classical | X25519 ECDH | 32 bytes | 128-bit classical |
| Post-quantum | ML-KEM-768 (NIST FIPS 203) | EK: 1184 B, CT: 1088 B | NIST level 3 |
| Combined | Hybrid binding via BLAKE3 | — | Secure if either holds |

Both keys are derived from the same 32-byte seed stored in the `.key` file.

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

**UX limitation:** `arsenic_list_recipients` returns the *ephemeral* X25519
public keys of each keyslot, not the recipients' own public keys (which are
not stored, for anonymity). To identify which slot belongs to a given
contact, the caller must attempt decapsulation with the contact's private key
(`arsenic_find_matching_key`). A future improvement would let the key manager
map contact names to slot indices directly.

### Correlated X25519 and ML-KEM entropy

The ML-KEM-768 key pair is deterministically derived from the same 32-byte
X25519 seed via BLAKE3 (`"Arsenic ML-KEM d"` / `"Arsenic ML-KEM z"`).
This means both the classical and post-quantum components share a single
root secret rather than independent entropy sources.

Security properties:
- The derivation is sound: BLAKE3 with domain separation is modelled as
  a PRF; given a uniformly random 32-byte seed, both derived keys are
  indistinguishable from independent uniform random keys.
- The design relies on the OS CSPRNG (`rand::random()` → `getrandom`) to
  produce that initial seed. Any weakness in the seed weakens both
  components simultaneously rather than independently.
- NIST FIPS 203 recommends independent `d` and `z` random values for
  ML-KEM key generation. Arsenic derives them via BLAKE3 instead, which is
  secure under the PRF assumption but constitutes an additional hypothesis
  beyond the bare FIPS 203 model.

**Trade-off accepted for usability:** a single 32-byte `.key` file managing
the full hybrid keypair is substantially simpler than a 64-byte or two-file
approach. The risk is acceptable given a trustworthy OS RNG.

---

## Format summary

```
┌──────────────────────────────────────────────┐  ← offset 0x00
│  Section pré-MAC   77 bytes  (pre-MAC)        │  plaintext, integrity-protected
│  HeaderMAC         32 bytes                   │  BLAKE3_keyed_hash(KEK, pre-MAC)
│  WrappedDEK        48 bytes                   │  AEAD-encrypted DEK (symmetric keyslot)
│  hybrid_count       4 bytes                   │  number of hybrid keyslots
│  Keyslot_0       1180 bytes  ┐               │  X25519+ML-KEM-768 wrapped DEK
│  Keyslot_1       1180 bytes  │ × N           │
│  ProtectedMeta    ≥66 bytes  ┘               │  AEAD-encrypted TLV (Merkle root, size…)
└──────────────────────────────────────────────┘  ← offset = header_total_size (≥227 bytes)
┌──────────────────────────────────────────────┐
│  Block 0: ciphertext + 16-byte AEAD tag       │
│  Block 1: ciphertext + 16-byte AEAD tag       │  blocks processed sequentially,
│  …                                            │  parallel file-level processing in GUI
└──────────────────────────────────────────────┘
  ↓ BLAKE3 Merkle tree over all encrypted blocks (root stored in ProtectedMeta)
```

Full specification: [`FORMAT.md`](FORMAT.md) · Rendered: [`FORMAT.html`](FORMAT.html).

---

## License

GPL-3.0-only — see [`LICENSE`](../LICENSE).
