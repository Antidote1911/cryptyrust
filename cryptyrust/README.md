> [Version française](README_fr.md)

# cryptyrust

Dual-mode binary: launches the native GUI when called without arguments, or runs as a CLI tool when arguments are supplied.

Built with [egui](https://github.com/emilk/egui) / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe).

---

## Features

- **Drag-and-drop** — drop files directly onto the window
- **Automatic mode detection** — `.arsn` = decrypt, other = encrypt
- **Multi-file parallel encryption** via Rayon
- **Individual cancellation** of each in-progress operation
- **Post-quantum hybrid encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203)
- **ML-DSA-65 signatures** (NIST FIPS 204) — sign during encryption, auto-verified on decryption
- **Sender identity embedding** — sender's public keys embedded in the file header (plaintext); recipient auto-prompted to add sender as a contact after decryption
- **Automatic key-based decryption** — if a keystore key matches the file, no password is requested
- **Key manager** — generate hybrid keypairs (X25519 + ML-KEM + ML-DSA-65), manage contacts
- **Contact trust store** — verify ML-DSA-65 signatures against known contacts
- **Built-in benchmark** of AEAD ciphers
- **In-place password change** (rekey)
- **Recipient management** — add or remove asymmetric keyslots from an existing file
- Light / dark theme; settings persisted between sessions

---

## GUI Workflows

### Symmetric Encryption

1. Drop files or click **Add files**
2. Click **Encrypt**, enter the password (+ confirmation)
3. `.arsn` files are created in the same directory

### Asymmetric Encryption (passwordless)

1. Open **Keys → Key Manager**
2. Click **⚡ Generate** to create a keypair, or add a contact (paste their public key)
3. Click **Encrypt** → select recipients in the popup
4. The password becomes optional if at least one recipient is selected

### Signing

Each keypair generated with **⚡ Generate** includes an ML-DSA-65 signing key automatically.

1. In **Config** → **Signing key**, select the identity to sign with
2. Encrypt normally — the file is signed with the selected identity
3. On decryption the signature is verified automatically:
   - Green banner: "Signed by: alice ✓" (known contact)
   - Yellow banner: "Signed by unknown key" (valid but not in trust store)
   - Red banner: "Signature INVALID" (tampered file)

### Decryption

- **With stored key**: if a keystore key matches the file, decryption starts immediately without a popup
- **With password**: if no key matches, the popup asks for the password
- **Sender identity**: if the file contains sender info, a banner appears after decryption:
  "📨 From: alice — add to contacts?" with an **Add** button

---

## Configuration

**Config** menu:

| Setting | Options | Default |
|---|---|---|
| Argon2id strength | Interactive (256 MiB, ~1-3 s) · Sensitive (1 GiB, ~10-30 s) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |
| Signing key | Select identity from keystore | None |
| Benchmark | ⏱ Benchmark ciphers… | — |

Settings are persisted between sessions via eframe storage.

---

## CLI Usage

The `cryptyrust` binary runs as a CLI when any argument is passed.

### Encrypt / Decrypt

```bash
# Encrypt with password (prompts interactively)
cryptyrust -e file.txt

# Encrypt with password passed on the command line (not recommended)
cryptyrust -e file.txt -p "passphrase"

# Encrypt for recipients (ML-KEM-768, default)
cryptyrust -e file.txt -R alice -R bob

# Encrypt with ML-KEM-1024 (NIST Level 5, ~256-bit quantum security)
cryptyrust -e file.txt -R alice --kem-level 1024

# Encrypt + sign with an ML-DSA-65 signing key
cryptyrust -e file.txt -S alice

# Encrypt for recipients + sign
cryptyrust -e file.txt -R alice -S alice

# Decrypt (auto-tries all keystore keys, then prompts for password)
cryptyrust -d file.txt.arsn

# Decrypt with a specific identity file
cryptyrust -d file.txt.arsn -i ~/.config/cryptyrust/keys/alice.key

# Change password without re-encrypting the payload
cryptyrust --rekey file.txt.arsn

# Benchmark ciphers
cryptyrust --bench

# Full option list
cryptyrust --help
```

### Options

| Flag | Description |
|---|---|
| `-e FILE` | Encrypt FILE |
| `-d FILE` | Decrypt FILE |
| `--rekey FILE` | Change symmetric password in-place |
| `-p PASSWORD` | Password (not recommended — visible in shell history) |
| `-f FILE` | Read password from file |
| `-o PATH` | Output file or directory |
| `-R NAME_OR_FILE` | Add a recipient (repeatable) — contact name or `.key` file path |
| `-i KEY_FILE` | Identity file to try for decryption (repeatable) |
| `-S NAME_OR_FILE` | Sign with this ML-DSA-65 signing key (name or `.sigkey` file) |
| `--kem-level 768|1024` | ML-KEM security level for new keyslots |
| `--strength interactive|sensitive` | Argon2id preset |
| `--hdr-cipher CIPHER` | Header cipher: `deoxys-ii`, `xchacha20`, `aes-gcm-siv` |
| `--pld-cipher CIPHER` | Payload cipher: `deoxys-ii`, `xchacha20`, `aes-gcm-siv` |
| `--bench` | Benchmark all cipher combinations |

---

## Key Management

Keys are stored in `{config}/cryptyrust/keys/` and shared between the GUI and CLI.

```bash
# Generate an encryption keypair (X25519 + ML-KEM-768 + ML-DSA-65 signing key, all in one file)
cryptyrust keygen -n alice --store

# Generate keypair saved to a specific file
cryptyrust keygen -n alice -o alice.key

# Generate with ML-KEM-1024 support
cryptyrust keygen -n alice --store --kem-level 1024

# List all stored keypairs
cryptyrust keygen --list

# Show the public key of a .key file
cryptyrust keygen -y alice.key

# Generate a standalone ML-DSA-65 signing key (for use with -S in CLI)
cryptyrust keygen --sign -n alice --store
cryptyrust keygen --sign -n alice -o alice.sigkey

# List stored standalone signing keys
cryptyrust keygen --list-sign
```

> **Note on signing keys:** the GUI uses the ML-DSA-65 seed embedded in `.key` files (generated
> by `⚡ Generate`). The CLI uses standalone `.sigkey` files (generated by `keygen --sign`).
> Both produce the same format on disk — the seed is the same type in both cases.

---

## Recipient Management

```bash
# List keyslots in a file (probes keystore to identify owners)
cryptyrust recipients list file.txt.arsn

# Add a recipient to an existing file (requires symmetric password)
cryptyrust recipients add file.txt.arsn -R alice -p "passphrase"

# Remove a recipient by identity file
cryptyrust recipients remove file.txt.arsn -i alice.key -p "passphrase"

# Remove a recipient by slot index
cryptyrust recipients remove file.txt.arsn --slot 0 -p "passphrase"
```

---

## Building

```bash
cargo build --release -p cryptyrust
# Binary: target/release/cryptyrust
```

### Linux Dependencies

```bash
sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                 libxkbcommon-dev libssl-dev pkg-config
```

---

## Code Structure

```
cryptyrust/src/
├── main.rs          Entry point: GUI if no args, CLI otherwise
├── app.rs           Application state, business logic, job dispatch
├── cli.rs           Clap argument definitions
├── cli_runner.rs    CLI command implementations
├── job.rs           Encrypt/decrypt job management (Rayon thread pool)
├── file_utils.rs    Mode detection, output path generation
├── keystore.rs      Re-export of arsenic::keystore
└── ui/
    ├── mod.rs       Main rendering dispatch
    ├── layouts.rs   Menu bar, action bar, central panel, status banners
    └── components.rs Tables, popups, key manager, contact management
```
