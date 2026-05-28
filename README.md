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
- **XChaCha20-Poly1305** block encryption with per-block key and nonce derivation
- **Serpent-256-GCM** header cipher — protects the Data Encryption Key (DEK) envelope
- **Argon2id** key derivation with two strength levels (Interactive / Sensitive)
- **HMAC-SHA256 pre-authentication** — the header MAC is verified *before* running Argon2id, preventing denial-of-service via forged cost parameters
- **BLAKE3 Merkle tree** over all encrypted blocks — full-file integrity verified before any plaintext is written
- **Parallel block encryption and decryption** via Rayon — scales with CPU core count
- **In-place password change** (`--rekey`) — rewrites only the 256-byte header without touching the payload, with automatic crash-safe backup and recovery
- **DEK separation** — the Data Encryption Key is random and wrapped by the Key Encrypting Key; changing a password does not re-encrypt the payload
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
# Default strength (Interactive — 256 MB Argon2id)
cryptyrust_cli -e secret.pdf -p "correct horse battery staple"

# Sensitive strength (1 GB Argon2id — slower, stronger)
cryptyrust_cli -e secret.pdf --strength sensitive -p "my passphrase"

# Specify output file
cryptyrust_cli -e secret.pdf -o /tmp/secret.arsn -p "my passphrase"

# Read password from a file (UTF-8, no trailing newline)
cryptyrust_cli -e secret.pdf -f /path/to/passfile
```

Output: `secret.pdf.arsn` (or the path given with `-o`).

### Decrypt a file

```bash
cryptyrust_cli -d secret.pdf.arsn -p "correct horse battery staple"

# Specify output file
cryptyrust_cli -d secret.pdf.arsn -o /tmp/secret.pdf -p "my passphrase"
```

If no `-o` is given, Cryptyrust strips the `.arsn` suffix and resolves naming collisions automatically.

### Change password (rekey)

```bash
cryptyrust_cli --rekey secret.pdf.arsn
# Prompts interactively:
#   Current password:
#   New password (minimum 8 characters, longer is better):
#   Confirm new password:
```

Rekey rewrites only the 256-byte header in-place. The encrypted payload is never touched — the operation takes the same time regardless of file size. A `.bak` copy of the old header is written and flushed to disk *before* any modification; on success it is removed. If the process is interrupted (power cut, crash), the next `--rekey` call automatically restores the header from the backup.

### Full flag reference

```
cryptyrust_cli [OPTIONS] --encrypt <FILE> | --decrypt <FILE> | --rekey <FILE>

Options:
  -e, --encrypt <FILE>      File to encrypt
  -d, --decrypt <FILE>      File to decrypt
  -k, --rekey   <FILE>      Change password of an encrypted file in-place
  -o, --output  <PATH>      Output file or directory
  -p, --password <PASSWORD> Password (shell history risk — prefer interactive prompt)
  -f, --passwordfile <FILE> Read password from a file (UTF-8, no trailing newline)
      --strength <LEVEL>    Argon2id cost: interactive (default) | sensitive
  -h, --help                Print help
  -V, --version             Print version
```

---

## GUI Usage

1. **Drag and drop** files onto the window (or use *File → Add files…*).
2. Cryptyrust auto-detects the mode:
   - All dropped files are `.arsn` → **Decrypt** mode
   - All dropped files are plaintext → **Encrypt** mode
   - Mixed → mode selector appears
3. Enter your password (and confirm on encryption).
4. Click **Encrypt** or **Decrypt**. Multiple files are processed in parallel.
5. To **change the password** of an `.arsn` file, select it alone and use the *Change password* action from the menu.

The Argon2id strength level and dark/light theme are persisted across sessions.

---

## Cryptographic Design

### Key hierarchy

```
Password ─── Argon2id(salt, t, m, p) ──► KEK (32 bytes)
                                            │
                                            └─ Serpent-256-GCM ──► DEK (32 random bytes)
                                                                      │
                                            ┌─────────────────────────┘
                                            │
                         per-block key = BLAKE3_keyed_hash(DEK, block_index)
                         per-block nonce = BLAKE3_derive_key("Arsenic V2 Block Nonce",
                                                              base_nonce ‖ block_index)
                                            │
                                            └─ XChaCha20-Poly1305 ──► encrypted block
```

- The **DEK** (Data Encryption Key) is generated fresh for every encryption and stored encrypted inside the header envelope. Changing a password only re-wraps the DEK under a new KEK — the payload is untouched.
- Block keys and nonces are deterministically derived from the DEK and the block index, so all blocks can be **encrypted and decrypted in parallel**.

### Header pre-authentication

Before running the expensive Argon2id derivation, Cryptyrust verifies a cheap **HMAC-SHA256 header MAC**:

```
PreKey     = HMAC-SHA256(key = password,  data = salt)
HeaderMAC  = HMAC-SHA256(key = PreKey,    data = header[0x00..0x4C])
```

A forged or corrupted header is rejected immediately without spending Argon2id memory, preventing denial-of-service attacks based on inflated `m_cost` parameters.

### Integrity verification

Every encrypted block is hashed with **BLAKE3** to produce a leaf. After all blocks are decrypted, the Merkle root is recomputed and compared with the root stored in the header envelope. **No plaintext is written until the entire file passes Merkle verification.**

### Argon2id strength levels

| Level | t (iterations) | m (memory) | p (parallelism) | Typical cost |
|---|---|---|---|---|
| Interactive (default) | 4 | 256 MB | 4 | ~1–3 s |
| Sensitive | 12 | 1 GB | 4 | ~10–30 s |

### Algorithms summary

| Role | Algorithm | Library |
|---|---|---|
| Password-based key derivation | Argon2id | RustCrypto |
| Header envelope encryption | Serpent-256-GCM | custom (NIST SP 800-38D) |
| Header MAC (pre-auth) | HMAC-SHA256 | RustCrypto |
| Block encryption | XChaCha20-Poly1305 | RustCrypto |
| Block key/nonce derivation | BLAKE3 keyed hash / derive\_key | BLAKE3 team |
| File integrity (Merkle leaves) | BLAKE3 hash | BLAKE3 team |
| In-memory secret handling | `Secret<T>` (zeroize on drop) | custom |

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

The `--rekey` crash-safety mechanism protects against header corruption during a password change, but it does **not** protect against forgetting the new password before it has been confirmed to work.
