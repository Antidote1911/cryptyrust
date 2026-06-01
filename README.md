[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

> [Version française](README_fr.md)

# Cryptyrust

**Cross-platform file encryption — drag-and-drop GUI, CLI, and C FFI library.**

Pre-built binaries for Linux, macOS (universal) and Windows are available on the [releases page](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Features

- **Arsenic V1** format (`.arsn`) — fully documented in [`arsenic/FORMAT.md`](arsenic/FORMAT.md)
- **Post-quantum hybrid encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203). Resistant to future quantum computers (harvest-now-decrypt-later)
- **ML-DSA-65 signatures** (NIST FIPS 204) — optionally sign files during encryption; signature verified automatically on decryption
- **Drag-and-drop GUI** — drop files to encrypt or decrypt; mode auto-detected
- **CLI** for scripting and automation
- **Integrated key management**: encryption keypairs (X25519 + ML-KEM) and signing keys (ML-DSA-65)
- Three independently selectable **AEAD ciphers** for header and payload
- **Argon2id** key derivation (Interactive 256 MiB / Sensitive 1 GiB)
- **Password change** without re-encrypting the payload
- **Built-in benchmark** — find the fastest cipher for your machine
- Cross-platform: Linux, Windows, macOS

---

## Project Structure

| Crate / Directory | Output | Description |
|---|---|---|
| [`arsenic/`](arsenic/) | library | Cryptographic core — [README](arsenic/README.md) · [Format spec](arsenic/FORMAT.md) |
| [`cryptyrust/`](cryptyrust/) | `cryptyrust` | GUI + CLI + key management (single binary) — [README](cryptyrust/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | C-compatible FFI layer — [README](ffi/README.md) |

---

## GUI — Usage

1. **Drag and drop** files onto the window, or click **Add files**.
2. Mode is auto-detected: `.arsn` → **Decrypt**, plaintext → **Encrypt**.
3. Click **Encrypt** / **Decrypt** and enter the password.

### Encrypting for recipients (passwordless)

1. Open **Keys → Key Manager** → generate a keypair or add a contact.
2. When encrypting, select recipients in the popup — the password becomes optional.
3. The recipient decrypts with their private key, without knowing the password.

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
# Encrypt with password
cryptyrust -e document.pdf -p "my secret passphrase"

# Encrypt for recipients (ML-KEM-768, default)
cryptyrust -e document.pdf -R alice -R bob

# Encrypt with ML-KEM-1024 (NIST Level 5, ~256-bit quantum security)
cryptyrust -e document.pdf -R alice --kem-level 1024

# Encrypt + sign with ML-DSA-65
cryptyrust -e document.pdf -p "passphrase" -S alice

# Decrypt (auto-tries stored keys, verifies signature if present)
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
# Encryption keypairs (X25519 + ML-KEM-768/1024)
cryptyrust keygen -n alice --store           # generate and save to keystore
cryptyrust keygen -n alice -o alice.key      # generate to file
cryptyrust keygen --list                     # list stored keypairs
cryptyrust keygen -y alice.key               # show public key of a .key file

# ML-DSA-65 signing keys
cryptyrust keygen --sign -n alice --store    # generate signing key → keystore
cryptyrust keygen --sign -n alice -o alice.sigkey
cryptyrust keygen --list-sign                # list stored signing keys
```

The keystore is shared between the GUI and CLI — a key generated in one mode is immediately available in the other.

## Signing

```bash
cryptyrust -e document.pdf -S alice -p "passphrase"   # encrypt + sign
cryptyrust -d document.pdf.arsn -p "passphrase"       # decrypt (auto-verifies signature)
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
# CLI → target/release/cryptyrust_cli
# GUI → target/release/cryptyrust
# keygen → target/release/crypty-keygen
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
