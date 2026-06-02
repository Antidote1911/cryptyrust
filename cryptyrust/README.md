# cryptyrust

Dual-mode binary: launches the native GUI when called without arguments, or runs as a CLI tool when arguments are supplied.

Built with [egui](https://github.com/emilk/egui) / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe).

---

## Features

- **Drag-and-drop** — drop files directly onto the window
- **Automatic mode detection** — `.arsn` / `.arsn.armor` = decrypt, other = encrypt
- **Multi-file parallel encryption** via Rayon
- **Individual cancellation** of each in-progress operation
- **Post-quantum hybrid encryption** — X25519 + ML-KEM-768 or ML-KEM-1024 (NIST FIPS 203)
- **Multiple passphrase keyslots** — up to 15 extra passwords on the same file
- **ASCII armor** — base64 output for email/text channels; auto-detected on decrypt
- **Optional zstd compression** — levels 1–22, with size-leak warning
- **Automatic key-based decryption** — if a keystore key matches, no password popup
- **Key manager** — generate hybrid keypairs, manage contacts
- **Built-in benchmark** of AEAD ciphers
- **In-place password change** (rekey — O(1), payload untouched)
- **Recipient management** — add or remove asymmetric keyslots post-encryption
- Light / dark theme; settings persisted between sessions

---

## GUI Workflows

### Symmetric Encryption

1. Drop files or click **Add files**
2. Click **Encrypt**, enter the password (+ confirmation)
3. `.arsn` files are created in the same directory (or `.arsn.armor` if armor is enabled)

### Asymmetric Encryption (passwordless)

1. Open **Keys → Key Manager** → **⚡ Generate** to create a keypair
2. Add a contact (paste their public key or drag their `.pubkey` file)
3. Click **Encrypt** → select recipients in the popup

### Decryption

- **With stored key**: if a keystore key matches the file (binary or armored), decryption starts immediately
- **With password**: if no key matches, the popup asks for the password
- **Armored files**: `.arsn.armor` files are auto-detected and dearmored transparently
- **Sender identity**: if the file contains sender info, a banner offers to add them as a contact

---

## Configuration

**Config** menu:

| Setting | Options | Default |
|---|---|---|
| Argon2id strength | Interactive (256 MiB) · Sensitive (1 GiB) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |
| Compression | Off · zstd level 1–22 | Off |
| ASCII Armor | Off · On | Off |
| Benchmark | ⏱ Benchmark ciphers… | — |

---

## CLI Usage

### Encrypt / Decrypt

```bash
cryptyrust -e file.txt                       # password prompt
cryptyrust -e file.txt -p "passphrase"       # inline password (shell history risk)
cryptyrust -e file.txt -R alice -R bob       # recipients (ML-KEM-768)
cryptyrust -e file.txt -R alice --kem-level 1024  # ML-KEM-1024
cryptyrust -e file.txt --armor               # ASCII-armored output (.arsn.armor)
cryptyrust -e file.txt --compress            # zstd level 3 (default)
cryptyrust -e file.txt --compress 9          # zstd level 9
cryptyrust -e file.txt --compress 6 --armor  # combined

cryptyrust -d file.txt.arsn                  # auto-tries keystore, then password
cryptyrust -d file.txt.arsn.armor            # armor auto-detected
cryptyrust -d file.txt.arsn -i my.key        # specific identity

cryptyrust --rekey file.txt.arsn             # change password (payload untouched)
cryptyrust --bench                           # benchmark ciphers
```

### Options

| Flag | Description |
|---|---|
| `-e FILE` | Encrypt FILE |
| `-d FILE` | Decrypt FILE |
| `--rekey FILE` | Change password in-place |
| `-p PASSWORD` | Password (shell history risk) |
| `-f FILE` | Read password from file |
| `-o PATH` | Output file or directory |
| `-R NAME_OR_FILE` | Add recipient (repeatable) |
| `-i KEY_FILE` | Identity file for decryption (repeatable) |
| `--kem-level 768|1024` | ML-KEM security level |
| `--strength interactive|sensitive` | Argon2id preset |
| `--hdr-cipher CIPHER` | Header cipher: `deoxys-ii`, `xchacha20`, `aes-gcm-siv` |
| `--pld-cipher CIPHER` | Payload cipher |
| `--armor` / `-a` | ASCII-armor encrypted output |
| `--compress [LEVEL]` | zstd compression (level 1–22, default 3) |
| `--bench` | Benchmark all cipher combinations |

---

## Key Management

```bash
cryptyrust keygen -n alice --store           # save to shared keystore
cryptyrust keygen -n alice -o alice.key      # save to file
cryptyrust keygen -n alice --store --kem-level 1024
cryptyrust keygen --list
cryptyrust keygen -y alice.key               # show public key
```

---

## Recipient Management

```bash
cryptyrust recipients list file.txt.arsn
cryptyrust recipients add file.txt.arsn -R alice -p "passphrase"
cryptyrust recipients remove file.txt.arsn -i alice.key -p "passphrase"
cryptyrust recipients remove file.txt.arsn --slot 0 -p "passphrase"
```

---

## Passphrase Slot Management

```bash
# Count extra passphrase slots
cryptyrust passphrase list file.txt.arsn

# Add an extra passphrase (any existing password authenticates)
cryptyrust passphrase add file.txt.arsn -p "existing" --new-pass "extra"
cryptyrust passphrase add file.txt.arsn --new-pass-file extra_pw.txt

# Remove an extra passphrase (primary password required for HeaderMAC)
cryptyrust passphrase remove file.txt.arsn -p "primary" --remove-pass "extra"
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
    └── components.rs Tables, popups, key manager, About window
```
