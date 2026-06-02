[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

# Cryptyrust

**Cross-platform file encryption — drag-and-drop GUI, CLI, and C FFI library.**

Pre-built binaries for Linux, macOS (universal) and Windows are available on the [releases page](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Features

- **Arsenic V1** format (`.arsn`) — fully documented in [`arsenic/FORMAT.md`](arsenic/FORMAT.md)
- **Post-quantum hybrid encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203). Resistant to harvest-now-decrypt-later attacks
- **Sender identity embedding** — sender's public keys stored unencrypted in the file header; recipient is automatically prompted to add the sender as a contact after decryption (no separate `.pubkey` file exchange needed)
- **Drag-and-drop GUI** — drop files to encrypt or decrypt; mode auto-detected
- **CLI** for scripting and automation — same binary, same keystore
- **Integrated key management**: one keypair per identity (X25519 + ML-KEM), shared between GUI and CLI
- Three independently selectable **AEAD ciphers** for header and payload
- **Argon2id** key derivation (Interactive 256 MiB / Sensitive 1 GiB)
- **Password change** without re-encrypting the payload
- **Built-in benchmark** — find the fastest cipher combination for your machine
- Cross-platform: Linux, Windows, macOS

---

## Project Structure

| Crate / Directory | Output | Description |
|---|---|---|
| [`arsenic/`](arsenic/) | library | Cryptographic core — [README](arsenic/README.md) · [Format spec](arsenic/FORMAT.md) |
| [`cryptyrust/`](cryptyrust/) | `cryptyrust` | GUI + CLI + key management (single binary) — [README](cryptyrust/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | C-compatible FFI layer — [README](ffi/README.md) |

---

## GUI — Quick Start

1. **Drag and drop** files onto the window, or click **Add files**.
2. Mode is auto-detected: `.arsn` → **Decrypt**, plaintext → **Encrypt**.
3. Click **Encrypt** / **Decrypt** and enter the password.

### Encrypting for recipients (asymmetric, passwordless)

1. Open **Keys → Key Manager** → click **⚡ Generate** to create a keypair.
2. Share your public key with the sender (via the key manager export).
3. When encrypting, select recipients in the popup — the password becomes optional.
4. The recipient decrypts with their private key, no password required.

### Sender identity

If the encrypted file contains sender identity info (embedded by the sender), a banner
appears after decryption: **"📨 From: alice — add to contacts?"** — click **Add** to
add them automatically.

### Configuration

| Setting | Options | Default |
|---|---|---|
| Argon2id strength | Interactive (256 MiB) · Sensitive (1 GiB) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |

---

## CLI — Quick Usage

The `cryptyrust` binary acts as a CLI when called with arguments, or opens the GUI when called without arguments.

```bash
# Encrypt with password (interactive prompt)
cryptyrust -e document.pdf

# Encrypt for recipients (ML-KEM-768, default)
cryptyrust -e document.pdf -R alice -R bob

# Encrypt with ML-KEM-1024 (NIST Level 5, ~256-bit quantum security)
cryptyrust -e document.pdf -R alice --kem-level 1024

# Decrypt (auto-tries stored keys, falls back to password prompt)
cryptyrust -d document.pdf.arsn

# Decrypt with a specific key file
cryptyrust -d document.pdf.arsn -i ~/.config/cryptyrust/keys/alice.key

# Change password (does not re-encrypt the payload)
cryptyrust --rekey document.pdf.arsn

# Benchmark ciphers
cryptyrust --bench
```

---

## Key Management

```bash
# Generate an encryption keypair (X25519 + ML-KEM-768, all in one .key file)
cryptyrust keygen -n alice --store           # save to shared keystore
cryptyrust keygen -n alice -o alice.key      # save to specific file

# List stored keypairs
cryptyrust keygen --list

# Show public key of a .key file
cryptyrust keygen -y alice.key
```

The keystore (`{config}/cryptyrust/keys/`) is shared between the GUI and CLI.

### Recipient management

```bash
# List keyslots in an encrypted file
cryptyrust recipients list file.pdf.arsn

# Add a recipient (requires symmetric password)
cryptyrust recipients add file.pdf.arsn -R bob -p "passphrase"

# Remove a recipient (by identity file or slot index)
cryptyrust recipients remove file.pdf.arsn -i alice.key -p "passphrase"
cryptyrust recipients remove file.pdf.arsn --slot 0 -p "passphrase"
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

If you lose or forget your password, **your data cannot be recovered.** There is no backdoor or recovery mechanism. Use a password manager or keep a secure backup of your passphrase.

If you encrypted for asymmetric recipients without a password, losing the `.key` private key file is also unrecoverable.

---

## Library and Format

All cryptographic logic is in the [`arsenic`](arsenic/) crate.
See [`arsenic/README.md`](arsenic/README.md) for the API and [`arsenic/FORMAT.md`](arsenic/FORMAT.md) for the complete binary format specification of the Arsenic V1 format.
