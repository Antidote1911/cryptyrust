[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

# Cryptyrust

**Cross-platform file encryption with a drag-and-drop GUI and a CLI.**

Pre-built binaries for Linux, macOS (universal), and Windows are available on the [releases page](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [CLI Usage](#cli-usage)
- [GUI Usage](#gui-usage)
- [Cryptographic Design](#cryptographic-design)
- [Build Instructions](#build-instructions)
- [Data Loss Disclaimer](#data-loss-disclaimer)

---

## Features

- **Arsenic V2** format (`.arsn`) — the sole supported format
- **Selectable header cipher** — independently choose the algorithm used to encrypt the DEK envelope in the header:
  - Serpent-256-GCM *(default)*
  - AES-256-GCM-SIV
  - XChaCha20-Poly1305
- **Selectable payload cipher** — independently choose the algorithm used to encrypt payload blocks:
  - XChaCha20-Poly1305 *(default)*
  - AES-256-GCM-SIV
  - Serpent-256-GCM
- **Argon2id** key derivation with two strength presets (Interactive / Sensitive)
- **HMAC-SHA256 pre-authentication** — the header MAC is verified *before* running Argon2id, preventing denial-of-service via forged cost parameters
- **BLAKE3 Merkle tree** over all encrypted blocks — full-file integrity verified before any plaintext is written
- **Parallel block encryption and decryption** via Rayon — scales with CPU core count
- **In-place password change** (`--rekey`) — rewrites only the 256-byte header, with crash-safe `.bak` backup and automatic restore on corruption
- **DEK separation** — the Data Encryption Key is random and wrapped by the Key Encrypting Key; changing a password never re-encrypts the payload
- Cross-platform: Linux, Windows, macOS

---

## Project Structure

| Crate | Binary | Description |
|---|---|---|
| `core` | — | `cryptyrust_core` library — all cryptographic logic |
| `cli` | `cryptyrust_cli` | Command-line interface |
| `gui` | `cryptyrust` | Native GUI built with [egui](https://github.com/emilk/egui) |

---

## CLI Usage

### Encrypt a file

```bash
# Default strength (Interactive — 256 MB Argon2id) with default ciphers
cryptyrust_cli -e secret.pdf -p "correct horse battery staple"

# Sensitive strength (1 GB Argon2id — slower, stronger)
cryptyrust_cli -e secret.pdf --strength sensitive -p "my passphrase"

# Custom ciphers: AES-256-GCM-SIV header, Serpent-256-GCM payload
cryptyrust_cli -e secret.pdf --hdr-cipher aes-gcm-siv --pld-cipher serpent-gcm -p "my passphrase"

# Specify output file
cryptyrust_cli -e secret.pdf -o /tmp/secret.arsn -p "my passphrase"

# Read password from a file (UTF-8, no trailing newline)
cryptyrust_cli -e secret.pdf -f /path/to/passfile
```

Output: `secret.pdf.arsn` (or the path given with `-o`).

`--hdr-cipher` and `--pld-cipher` are ignored during decryption and rekey — the cipher IDs are always read from the file header.

### Decrypt a file

```bash
cryptyrust_cli -d secret.pdf.arsn -p "correct horse battery staple"

# Specify output file
cryptyrust_cli -d secret.pdf.arsn -o /tmp/secret.pdf -p "my passphrase"
```

Decryption reads the cipher IDs stored in the file header — no cipher selection is needed.

If no `-o` is given, Cryptyrust strips the `.arsn` suffix and resolves naming collisions automatically.

### Change password (rekey)

```bash
cryptyrust_cli --rekey secret.pdf.arsn
# Prompts interactively:
#   Current password:
#   New password (minimum 8 characters, longer is better):
#   Confirm new password:
```

Rekey rewrites only the 256-byte header in-place. The encrypted payload is **never touched** — the operation completes in constant time regardless of file size. The selected cipher algorithms are preserved unchanged.

A `.bak` copy of the original header is written and flushed to disk *before* any modification. On success it is removed. If the process is interrupted (power cut, crash), the next `--rekey` call automatically detects the corrupted magic bytes, restores the original header from the backup, and returns an error asking the user to retry.

### Full flag reference

```
Usage: cryptyrust_cli [OPTIONS] <--encrypt <FILE>|--decrypt <FILE>|--rekey <FILE>>

Options:
  -e, --encrypt <FILE>          File to encrypt
  -d, --decrypt <FILE>          File to decrypt
  -k, --rekey <FILE>            Change password of an encrypted file in-place
  -o, --output <PATH>           Output file (ignored for rekey)
  -p, --password <PASSWORD>     Password (shell history risk — prefer interactive prompt)
  -f, --passwordfile <FILE>     Read password from a file (UTF-8, no trailing newline)
      --strength <STRENGTH>     Argon2id cost preset: interactive (default) | sensitive
      --hdr-cipher <CIPHER>     Header envelope cipher (encryption only): serpent-gcm (default) | xchacha20 | aes-gcm-siv
      --pld-cipher <CIPHER>     Payload block cipher (encryption only): xchacha20 (default) | serpent-gcm | aes-gcm-siv
  -h, --help                    Print help
  -V, --version                 Print version
```

---

## GUI Usage

1. **Drag and drop** files onto the window, or use *File → Add files…*.
2. Cryptyrust auto-detects the mode:
   - All files are `.arsn` → **Decrypt** mode
   - All files are plaintext → **Encrypt** mode
   - Mixed selection → a warning is shown; resolve it before proceeding
3. Click **Encrypt** or **Decrypt**, enter your password (confirm on encryption).
4. Multiple files are processed in parallel with per-file progress bars.
5. To **change the password** of a single `.arsn` file, select it alone and click *Change password*.

### Algorithm configuration

Open the **Config** menu to independently configure (for encryption only):

| Setting | Options | Default |
|---|---|---|
| **Argon2id strength** | Interactive (256 MB) · Sensitive (1 GB) | Interactive |
| **Header cipher** | Serpent-256-GCM · AES-256-GCM-SIV · XChaCha20-Poly1305 | Serpent-256-GCM |
| **Payload cipher** | XChaCha20-Poly1305 · AES-256-GCM-SIV · Serpent-256-GCM | XChaCha20-Poly1305 |

The status bar at the bottom of the window always shows the active configuration. All settings are persisted between sessions.

---

## Cryptographic Design

### Key hierarchy

```
Password ──── Argon2id(salt, t_cost, m_cost, p_cost) ────► KEK (32 bytes)
                                                              │
                                              hdr_cipher ────┤
                                     (Serpent-GCM /         │
                                      AES-GCM-SIV /         ▼
                                      XChaCha20) ──► Encrypted envelope
                                                     contains:
                                                       DEK  (32 random bytes)
                                                       MerkleRoot (32 bytes)
                                                       OriginalSize, CompressedSize
                                                       BlockSizeID
                                                              │
                                              ┌───────────────┘
                                              │  DEK
                                              ▼
              per-block key   = BLAKE3_keyed_hash(DEK, u64_LE(block_index))
              per-block nonce = BLAKE3_derive_key("Arsenic V2 Block Nonce",
                                                   file_base_nonce ‖ u64_LE(N))
                                              │
                                pld_cipher ───┤
                       (XChaCha20 /          │
                        AES-GCM-SIV /        ▼
                        Serpent-GCM) ──► EncBlock_N
```

- The **DEK** (Data Encryption Key) is generated fresh for every encryption and stored encrypted inside the 256-byte header envelope. Changing a password only re-wraps the DEK under a new KEK — the entire payload is untouched.
- Block keys and nonces are deterministically derived from the DEK and the block index via BLAKE3, so all blocks can be **encrypted and decrypted in parallel** (Rayon).

### Header pre-authentication

Before running the expensive Argon2id derivation, Cryptyrust verifies a cheap **HMAC-SHA256 header MAC**:

```
PreKey    = HMAC-SHA256(key = password,  data = salt)
HeaderMAC = HMAC-SHA256(key = PreKey,    data = header[0x00..0x4C])
```

`PreKey` requires only one HMAC call — effectively free. A wrong password or forged/corrupted header is rejected immediately without spending Argon2id memory, preventing denial-of-service attacks based on inflated `m_cost` values.

### Integrity — BLAKE3 Merkle tree

Each encrypted block (including its AEAD tag) is hashed with **BLAKE3** to form a Merkle leaf. After all blocks are decrypted in parallel, the Merkle root is recomputed from the leaves and compared to the root stored inside the encrypted envelope. **No plaintext is written until the entire file passes Merkle verification.** Any substitution, deletion, reordering, or truncation of blocks is detected.

### Supported ciphers

All three supported ciphers provide authenticated encryption with a 16-byte tag. The cipher IDs are stored in the header at bytes `0x07` (header) and `0x08` (payload) and are covered by the `HeaderMAC`.

| ID | Algorithm | Nonce | Notes |
|----|-----------|-------|-------|
| `0x02` | **Serpent-256-GCM** | 12 bytes | Serpent-256 with NIST GCM mode; manual GHASH implementation |
| `0x03` | **XChaCha20-Poly1305** | 24 bytes | RustCrypto; default payload cipher |
| `0x04` | **AES-256-GCM-SIV** | 12 bytes | RustCrypto; nonce misuse-resistant |

> **Note on nonce handling** — the `kek_nonce` field in the header is always 12 bytes. When XChaCha20-Poly1305 is used as the header cipher, the 12-byte stored nonce is BLAKE3-expanded to 24 bytes. Block nonces are always derived as 24 bytes; 12-byte-nonce ciphers use the first 12 bytes.

### Argon2id strength presets

| Preset | t (iterations) | m (memory) | p (parallelism) | Typical time |
|--------|---------------|------------|-----------------|--------------|
| Interactive *(default)* | 4 | 256 MiB | 4 | ~1–3 s |
| Sensitive | 12 | 1 GiB | 4 | ~10–30 s |

The KDF parameters are stored in the header and covered by the `HeaderMAC`, so they cannot be silently downgraded.

### Algorithms summary

| Role | Algorithm | Source |
|------|-----------|--------|
| Key derivation | Argon2id | RustCrypto |
| Header MAC (pre-auth) | HMAC-SHA256 | RustCrypto |
| Header envelope encryption | Serpent-256-GCM / AES-256-GCM-SIV / XChaCha20-Poly1305 | custom / RustCrypto |
| Payload block encryption | XChaCha20-Poly1305 / AES-256-GCM-SIV / Serpent-256-GCM | RustCrypto / custom |
| Block key derivation | BLAKE3 keyed hash | BLAKE3 team |
| Block nonce derivation | BLAKE3 derive\_key | BLAKE3 team |
| File integrity (Merkle leaves) | BLAKE3 hash | BLAKE3 team |
| Key material erasure | `Secret<T>` (zeroize on drop) | custom |

---

## Build Instructions

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable)
- **Linux only:** development packages for X11 (required by egui):
  ```bash
  # Debian / Ubuntu
  sudo apt install libx11-dev libxrandr-dev libxi-dev libxcursor-dev libxinerama-dev
  # Fedora
  sudo dnf install libX11-devel libXrandr-devel libXi-devel
  ```

### Linux / macOS

```bash
cargo build --release
# CLI:  target/release/cryptyrust_cli
# GUI:  target/release/cryptyrust
```

#### macOS universal binary (Intel + Apple Silicon)

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create \
  target/x86_64-apple-darwin/release/cryptyrust_cli \
  target/aarch64-apple-darwin/release/cryptyrust_cli \
  -output cryptyrust_cli_universal
lipo -create \
  target/x86_64-apple-darwin/release/cryptyrust \
  target/aarch64-apple-darwin/release/cryptyrust \
  -output cryptyrust_universal
```

### Windows

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **Desktop development with C++** workload.
2. Ensure the MSVC target is active:
   ```bat
   rustup default stable-x86_64-pc-windows-msvc
   ```
3. Build:
   ```bat
   cargo build --release
   ```
   Binaries: `target\release\cryptyrust_cli.exe` and `target\release\cryptyrust.exe`.

---

## Data Loss Disclaimer

If you lose or forget your password, **your data cannot be recovered.** There is no back door and no password recovery mechanism. Use a password manager or another secure backup of your passphrase.

The `--rekey` crash-safety mechanism protects against header corruption during a password change, but it does **not** protect against forgetting the new password before confirming it works.
