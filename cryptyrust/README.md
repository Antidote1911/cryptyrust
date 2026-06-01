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
- **Post-quantum hybrid encryption** — select recipients (X25519 + ML-KEM-768)
- **Automatic key-based decryption** — if a keystore key matches the file, no password is requested
- **Key manager** — generate hybrid keypairs, manage contacts
- **Built-in benchmark** of AEAD ciphers
- **In-place password change** (rekey)
- Light / dark theme; settings persisted between sessions

---

## Symmetric Encryption Workflow

1. Drop files or click **Add files**
2. Click **Encrypt**, enter the password (+ confirmation)
3. `.arsn` files are created in the same directory

## Asymmetric Encryption Workflow (passwordless)

1. Open **Keys → Key Manager**
2. Generate a keypair (`⚡ Generate`) or add a contact (X25519 + ML-KEM-768 public key)
3. Click **Encrypt** → select recipients in the popup
4. The password becomes optional if at least one recipient is selected

## Decryption Workflow

- **With stored key**: if a keystore key matches the file, decryption starts immediately without a popup
- **With password**: if no key matches, the popup asks for the password
- **Manual selection**: in the popup, explicitly choose which key to use

---

## Configuration

**Config** menu:

| Setting | Options | Default |
|---|---|---|
| Argon2id strength | Interactive (256 MiB, ~1-3 s) · Sensitive (1 GiB, ~10-30 s) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |
| Benchmark | ⏱ Benchmark ciphers… | — |

Settings are persisted between sessions via eframe storage.

---

## CLI Usage

```bash
cryptyrust -e file.txt -p "passphrase"             # encrypt (password)
cryptyrust -d file.txt.arsn                        # decrypt (auto-tries keystore)
cryptyrust -e file.txt -R alice -R bob             # encrypt for recipients (ML-KEM-768)
cryptyrust -e file.txt -R alice --kem-level 1024   # encrypt with ML-KEM-1024 (NIST Level 5)
cryptyrust -e file.txt -S alice                    # encrypt + sign with ML-DSA-65 key
cryptyrust --rekey file.txt.arsn                   # change password
cryptyrust --bench                                 # benchmark ciphers
cryptyrust --help                                  # full option list
```

## Key Management

```bash
# Encryption keypairs (X25519 + ML-KEM)
cryptyrust keygen -n alice --store           # generate keypair → shared keystore
cryptyrust keygen -n alice -o alice.key      # generate keypair → specific file
cryptyrust keygen --list                     # list all stored keypairs
cryptyrust keygen -y alice.key               # show public key of a .key file

# ML-DSA-65 signing keys
cryptyrust keygen --sign -n alice --store    # generate signing key → shared store
cryptyrust keygen --sign -n alice -o alice.sigkey  # generate → specific file
cryptyrust keygen --list-sign                # list stored signing keys
```

## Building

```bash
cargo build --release -p cryptyrust
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
├── main.rs          Entry point, eframe initialisation
├── app.rs           Application state, business logic
├── job.rs           Encrypt/decrypt job management (Rayon)
├── file_utils.rs    Mode detection, output path generation
├── keystore.rs      Re-export of arsenic::keystore
└── ui/
    ├── mod.rs       Main rendering dispatch
    ├── layouts.rs   Menu bar, action bar, central panel
    └── components.rs Tables, popups, key manager
```
