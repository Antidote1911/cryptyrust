[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

# Cryptyrust

**Simple cross-platform file encryption with a drag-and-drop GUI and a CLI.**

Pre-built binaries for Linux, macOS (universal), and Windows are available on the [releases page](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [CLI Usage](#cli-usage)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Technical Description](#technical-description)
- [Build Instructions](#build-instructions)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
- [Data Loss Disclaimer](#data-loss-disclaimer)

---

## Features

- Three authenticated encryption algorithms: AES-256-GCM, AES-256-GCM-SIV, XChaCha20Poly1305
- Password-based key derivation with Argon2id (three strength levels)
- Streaming encryption — works on files of any size
- Optional BLAKE3 hash of the output file
- Automatic algorithm detection on decryption
- Optional PEM (base64 text) output format — `.crypty.pem` — CLI and GUI
- Cross-platform: Linux, Windows, macOS

> **Compatibility notice:** v1.1.0 files are **not compatible** with v1.0.0. The header is now used as Additional Authenticated Data (AAD), which changes the ciphertext structure.

---

## Project Structure

| Crate | Description |
|---|---|
| `core` | Rust encryption/decryption library (`cryptyrust_core`) |
| `cli` | Command-line interface (`cryptyrust_cli`) |
| `gui` | Native GUI built with [egui](https://github.com/emilk/egui) |

---

## CLI Usage

```bash
# Encrypt a file (default algorithm: AES-256-GCM)
./cryptyrust_cli -e test.mp4 -p 12345678

# Decrypt a file (algorithm is auto-detected)
./cryptyrust_cli -d test.mp4.crypty -p 12345678

# Encrypt and show the BLAKE3 hash of the output
./cryptyrust_cli -e test.mp4 -p 12345678 --hash
./cryptyrust_cli -d test.mp4.crypty -p 12345678 --hash

# Choose an encryption algorithm with -a
./cryptyrust_cli -e test.mp4 -a aesgcm    -p 12345678   # AES-256-GCM (default)
./cryptyrust_cli -e test.mp4 -a aesgcmsiv -p 12345678   # AES-256-GCM-SIV
./cryptyrust_cli -e test.mp4 -a chacha    -p 12345678   # XChaCha20Poly1305

# Choose Argon2 key derivation strength with -s (default: interactive)
./cryptyrust_cli -e test.mp4 -p 12345678 -s interactive  # fast, for interactive use
./cryptyrust_cli -e test.mp4 -p 12345678 -s moderate     # balanced
./cryptyrust_cli -e test.mp4 -p 12345678 -s sensitive    # slow, maximum security

# Read the password from a file (UTF-8, no trailing newline)
./cryptyrust_cli -e test.mp4 -f /path/to/passfile

# Specify an output file name with -o
./cryptyrust_cli -e test.mp4 -o myEncryptedFile -p 12345678
./cryptyrust_cli -d myEncryptedFile -o myDecryptedFile -p 12345678

# Run an in-memory benchmark (no file written)
./cryptyrust_cli -e test.mp4 -p 12345678 --bench

# Encrypt to PEM (base64 text) format — output: test.mp4.crypty.pem
./cryptyrust_cli -e test.mp4 --pem -p 12345678

# Decrypt a PEM file (auto-detected from file content)
./cryptyrust_cli -d test.mp4.crypty.pem -p 12345678
```

If no output file is specified with `-o`, Cryptyrust generates an incremental unique filename with a `.crypty` extension.

The `-a` flag is ignored during decryption — the algorithm is read from the file header.

---

## Cryptographic Primitives

| Role | Algorithm | Library |
|---|---|---|
| Key derivation | [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2) | RustCrypto |
| Encryption | [AES-256-GCM](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) (stream mode) | RustCrypto |
| Encryption | [AES-256-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv) (stream mode) | RustCrypto |
| Encryption | [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) (stream mode) | RustCrypto |
| Integrity check | [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) | BLAKE3 team |

All AEAD ciphers are used in [STREAM mode](https://github.com/miscreant/meta/wiki/STREAM), which provides authenticated encryption over arbitrarily large files.

---

## Technical Description

### Key Derivation

A 32-byte key is derived from the user's password and a 16-byte random salt using **Argon2id**. The salt is stored in the file header and is unique per encryption, preventing pre-computation attacks.

### Nonce

A random nonce is generated for each encryption:

| Algorithm | Nonce length |
|---|---|
| AES-256-GCM | 8 bytes |
| AES-256-GCM-SIV | 8 bytes |
| XChaCha20Poly1305 | 20 bytes |

Nonces are 4 bytes shorter than the standard size for each algorithm because STREAM mode reserves the last 4 bytes for a little-endian counter, which is incremented after each encrypted chunk.

### Additional Authenticated Data (AAD)

The entire 64-byte header is passed as AAD to the AEAD stream cipher. Any modification to the header (magic number, algorithm, salt, nonce, or padding) causes decryption to fail with an authentication error. This is what makes v1.1.0 files incompatible with v1.0.0.

### File Format

```
[ 4 bytes ] Magic number (43 52 59 50)
[ 2 bytes ] Header version
[ 2 bytes ] Algorithm identifier
[ 2 bytes ] Argon2 strength
[16 bytes ] Argon2 salt (random)
[16 bytes ] Reserved (zeros, for future use)
[ N bytes ] Nonce (8 bytes for AES, 20 bytes for XChaCha20Poly1305)
[ P bytes ] Padding (zeros, to reach a fixed 64-byte header)
[ ...     ] Encrypted chunks (BUFFER_SIZE + 16-byte authentication tag each)
```

See [FORMAT.md](FORMAT.md) for the detailed binary format with examples.

Both the CLI (`--pem` flag) and the GUI support a PEM output variant (`.crypty.pem`): the same binary structure is base64-encoded and wrapped between `-----BEGIN CRYPTYRUST ENCRYPTED DATA-----` and `-----END CRYPTYRUST ENCRYPTED DATA-----` lines, making the encrypted file safe to copy-paste as plain text. PEM files are auto-detected on decryption — no flag needed.

---

## Build Instructions

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable)

### Linux

```bash
cargo build --release
# CLI:  target/release/cryptyrust_cli
# GUI:  target/release/cryptyrust
```

### macOS

```bash
cargo build --release
# CLI:  target/release/cryptyrust_cli
# GUI:  target/release/cryptyrust
```

To build a universal binary (Intel + Apple Silicon):

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create \
  target/x86_64-apple-darwin/release/cryptyrust_cli \
  target/aarch64-apple-darwin/release/cryptyrust_cli \
  -output cryptyrust_cli
lipo -create \
  target/x86_64-apple-darwin/release/cryptyrust \
  target/aarch64-apple-darwin/release/cryptyrust \
  -output cryptyrust
```

### Windows

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **C++ build tools** workload.
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
