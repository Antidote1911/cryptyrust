[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

# Cryptyrust

**Cross-platform file encryption — drag-and-drop GUI, CLI, and C FFI library.**

Pre-built binaries for Linux, macOS (universal) and Windows are available on the [releases page](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Features

- **Arsenic V1** format (`.arsn`) — fully documented in [`arsenic/FORMAT.md`](arsenic/FORMAT.md)
- **Post-quantum hybrid encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203)
- **Multiple passphrase keyslots** — up to 15 independent passwords per file; any unlocks it
- **ASCII armor** — base64 transport encoding for email / text channels; auto-detected on decrypt
- **Optional zstd compression** — compress before encrypting (levels 1–22); size-leak warning shown
- **Drag-and-drop GUI** — drop `.arsn` or `.arsn.armor` files to decrypt; plaintext to encrypt
- **CLI** for scripting and automation — same binary, same keystore
- **Integrated key management** — X25519 + ML-KEM keypairs, shared between GUI and CLI
- Three independently selectable **AEAD ciphers** for header and payload
- **Argon2id** key derivation (Interactive 256 MiB / Sensitive 1 GiB)
- **Password change** without re-encrypting the payload — O(1) regardless of file size
- **Recipient management** — add/remove asymmetric keyslots post-encryption
- **Built-in benchmark** — find the fastest cipher for your machine
- Cross-platform: Linux, Windows, macOS

---

## Project Structure

| Crate / Directory | Output | Description |
|---|---|---|
| [`arsenic/`](arsenic/) | library | Cryptographic core — [README](arsenic/README.md) · [Format spec](arsenic/FORMAT.md) |
| [`cryptyrust/`](cryptyrust/) | `cryptyrust` | GUI + CLI + key management — [README](cryptyrust/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | C-compatible FFI layer — [README](ffi/README.md) |

---

## GUI — Quick Start

1. **Drag and drop** files onto the window, or click **Add files**.
2. Mode is auto-detected: `.arsn` / `.arsn.armor` → **Decrypt**, plaintext → **Encrypt**.
3. Click **Encrypt** / **Decrypt** and enter the password.

### Encrypting for recipients (asymmetric, passwordless)

1. Open **Keys → Key Manager** → click **⚡ Generate** to create a keypair.
2. Share your `.pubkey` file with correspondents.
3. When encrypting, select recipients in the popup — the password becomes optional.

### Configuration options

| Setting | Options | Default |
|---|---|---|
| Argon2id strength | Interactive (256 MiB) · Sensitive (1 GiB) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |
| Compression | Off · zstd level 1–22 | Off |
| ASCII Armor | Off · On | Off |

---

## CLI — Quick Usage

```bash
# Encrypt with password
cryptyrust -e document.pdf

# Encrypt for recipients
cryptyrust -e document.pdf -R alice -R bob

# Encrypt with ML-KEM-1024 (NIST Level 5)
cryptyrust -e document.pdf -R alice --kem-level 1024

# Encrypt with ASCII armor output (.arsn.armor)
cryptyrust -e document.pdf --armor

# Encrypt with zstd compression (level 3, default; or specify 1–22)
cryptyrust -e document.pdf --compress
cryptyrust -e document.pdf --compress 9

# Combine compression + armor
cryptyrust -e document.pdf --compress 6 --armor

# Decrypt (auto-detects armor, auto-tries stored keys)
cryptyrust -d document.pdf.arsn
cryptyrust -d document.pdf.arsn.armor

# Change password without re-encrypting
cryptyrust --rekey document.pdf.arsn

# Benchmark ciphers
cryptyrust --bench
```

---

## Key Management

```bash
# Generate a keypair (X25519 + ML-KEM-768)
cryptyrust keygen -n alice --store
cryptyrust keygen -n alice -o alice.key

# List stored keypairs
cryptyrust keygen --list

# Export public key
cryptyrust keygen -y alice.key
```

### Recipient management

```bash
cryptyrust recipients list file.pdf.arsn
cryptyrust recipients add file.pdf.arsn -R bob -p "passphrase"
cryptyrust recipients remove file.pdf.arsn -i alice.key -p "passphrase"
cryptyrust recipients remove file.pdf.arsn --slot 0 -p "passphrase"
```

### Passphrase slot management

```bash
# Count extra passphrase slots
cryptyrust passphrase list file.pdf.arsn

# Add a passphrase slot (any existing password authenticates)
cryptyrust passphrase add file.pdf.arsn -p "primary" --new-pass "extra"

# Remove an extra passphrase slot (primary password required)
cryptyrust passphrase remove file.pdf.arsn -p "primary" --remove-pass "extra"
```

---

## Building

### Prerequisites

- [Rust toolchain](https://rustup.rs/) stable
- **Linux only** — X11 / Wayland development packages:
  ```bash
  sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                   libxkbcommon-dev libssl-dev pkg-config
  ```

### Build

```bash
cargo build --release
# Binary: target/release/cryptyrust
```

### macOS universal binary

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create target/x86_64-apple-darwin/release/cryptyrust \
             target/aarch64-apple-darwin/release/cryptyrust \
             -output cryptyrust_universal
```

---

## Data Loss Warning

If you lose or forget your password, **your data cannot be recovered.** There is no backdoor.
Use a password manager or keep a secure backup of your passphrase.

Losing your `.key` file when you encrypted for recipients without a password is also unrecoverable.

---

## Library and Format

All cryptographic logic is in the [`arsenic`](arsenic/) crate.
See [`arsenic/README.md`](arsenic/README.md) for the API and [`arsenic/FORMAT.md`](arsenic/FORMAT.md) for the complete binary format specification.
