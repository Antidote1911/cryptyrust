> [Version française](README_fr.md)

# arsenic

Pure-Rust cryptographic library implementing the **Arsenic V1** file encryption format (`.arsn`).

Used by [`cryptyrust_cli`](../cli), the [`cryptyrust`](../gui) GUI, the [`arsenic_ffi`](../ffi) C FFI layer, and [`crypty-keygen`](../crypty-keygen).

---

## Features

- **Hybrid post-quantum asymmetric encryption** — X25519 + ML-KEM-768 (NIST FIPS 203). Each recipient gets an independent keyslot; files stay decryptable by quantum computers *and* classical ones
- **Three selectable AEAD ciphers**, independently configurable for header and payload:
  - `Deoxys-II-256` — tweakable block cipher AEAD *(default header cipher)*
  - `XChaCha20-Poly1305` — 192-bit nonce, software-friendly *(default payload cipher)*
  - `AES-256-GCM-SIV` — nonce-misuse resistant
- **Argon2id** key derivation with two presets (`Interactive` 256 MiB / `Sensitive` 1 GiB) plus a fast pre-auth pass (~2 ms) to reject wrong passwords before the full KDF
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
│  HeaderMAC         32 bytes                   │  HMAC-SHA256(KEK, pre-MAC)
│  WrappedDEK        48 bytes                   │  AEAD-encrypted DEK (symmetric keyslot)
│  hybrid_count       4 bytes                   │  number of hybrid keyslots
│  Keyslot_0       1180 bytes  ┐               │  X25519+ML-KEM-768 wrapped DEK
│  Keyslot_1       1180 bytes  │ × N           │
│  ProtectedMeta    ≥76 bytes  ┘               │  AEAD-encrypted TLV (Merkle root, sizes…)
└──────────────────────────────────────────────┘  ← offset = header_total_size (≥237 bytes)
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
