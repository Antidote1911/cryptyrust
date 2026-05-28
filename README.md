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
- [C / C++ FFI](#c--c-ffi)
- [Build Instructions](#build-instructions)
- [Data Loss Disclaimer](#data-loss-disclaimer)

---

## Features

- **Arsenic V1** format (`.arsn`) — the sole supported format
- **Selectable header cipher** — independently choose the algorithm used to encrypt the DEK keyslot and metadata:
  - Deoxys-II-256 *(default)*
  - AES-256-GCM-SIV
  - XChaCha20-Poly1305
- **Selectable payload cipher** — independently choose the algorithm used to encrypt payload blocks:
  - XChaCha20-Poly1305 *(default)*
  - AES-256-GCM-SIV
  - Deoxys-II-256
- **Optional zstd compression** — per-block zstd before encryption; disabled by default
- **Optional metadata** — filename, comment, and timestamp stored encrypted inside the header
- **Argon2id** key derivation with two strength presets (Interactive / Sensitive)
- **Tiny Argon2id pre-authentication** — a cheap pre-auth key (t=1, m=8 MB) is used to verify the header MAC before running the full KDF, preventing fast offline oracle attacks while keeping wrong-password rejection fast
- **LUKS-style keyslot** — the DEK is wrapped in a 48-byte keyslot; password changes re-encrypt only the keyslot, never the payload
- **BLAKE3 Merkle tree v1** — domain-separated leaf and node hashes over all encrypted blocks; full-file integrity verified before any plaintext is written
- **Parallel block encryption and decryption** via Rayon — scales with CPU core count
- **In-place password change** (`--rekey`) — rewrites only the header in-place, with crash-safe `.bak` backup and automatic restore on corruption
- **Cipher benchmark** (`--bench` / GUI Config menu) — measures AEAD throughput on the local machine and recommends the fastest combination
- Cross-platform: Linux, Windows, macOS

---

## Project Structure

| Crate / Dir | Binary / Output | Description |
|---|---|---|
| `core` | — | `cryptyrust_core` library — all cryptographic logic |
| `cli` | `cryptyrust_cli` | Command-line interface |
| `gui` | `cryptyrust` | Native GUI built with [egui](https://github.com/emilk/egui) |
| `ffi` | `libcryptyrust_ffi.so` / `.a` | C-compatible FFI layer for embedding in C / C++ / Qt projects |
| `ffi_test/` | `arsenic_test` | Minimal C++ CLI demo (encrypt / decrypt / bench) |

---

## CLI Usage

### Encrypt a file

```bash
# Default strength (Interactive — 256 MB Argon2id) with default ciphers
cryptyrust_cli -e secret.pdf -p "correct horse battery staple"

# Sensitive strength (1 GB Argon2id — slower, stronger)
cryptyrust_cli -e secret.pdf --strength sensitive -p "my passphrase"

# Custom ciphers: AES-256-GCM-SIV header, Deoxys-II-256 payload
cryptyrust_cli -e secret.pdf --hdr-cipher aes-gcm-siv --pld-cipher deoxys-ii -p "my passphrase"

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

Rekey replaces only the 48-byte DEK keyslot in-place. The encrypted payload and all metadata are **never touched** — the operation completes in constant time regardless of file size. The selected cipher algorithms and Argon2id parameters are preserved unchanged.

A `.bak` copy of the original header is written and flushed to disk *before* any modification. On success it is removed. If the process is interrupted (power cut, crash), the next `--rekey` call automatically detects the corrupted magic bytes, restores the original header from the backup, and returns an error asking the user to retry.

### Benchmark cipher throughput

```bash
cryptyrust_cli --bench
```

Runs a single Interactive Argon2id key derivation, then encrypts and decrypts 32 MiB of data with each of the three AEAD ciphers. Prints a throughput table and the recommended `--hdr-cipher` / `--pld-cipher` flags for the current machine.

**Note:** only the **payload cipher** is benchmarked on large data, because the header cipher processes only 32 bytes (the DEK) — a difference of nanoseconds regardless of algorithm. The benchmark result therefore reflects the payload cipher ranking only; the recommended combination sets both `hdr` and `pld` to the fastest cipher found.

### Full flag reference

```
Usage: cryptyrust_cli [OPTIONS] <--encrypt <FILE>|--decrypt <FILE>|--rekey <FILE>|--bench>

Options:
  -e, --encrypt <FILE>          File to encrypt
  -d, --decrypt <FILE>          File to decrypt
  -k, --rekey <FILE>            Change password of an encrypted file in-place
      --bench                   Benchmark AEAD cipher throughput on this machine
  -o, --output <PATH>           Output file (ignored for rekey)
  -p, --password <PASSWORD>     Password (shell history risk — prefer interactive prompt)
  -f, --passwordfile <FILE>     Read password from a file (UTF-8, no trailing newline)
      --strength <STRENGTH>     Argon2id cost preset: interactive (default) | sensitive
      --hdr-cipher <CIPHER>     Header envelope cipher (encryption only): deoxys-ii (default) | xchacha20 | aes-gcm-siv
      --pld-cipher <CIPHER>     Payload block cipher (encryption only): xchacha20 (default) | deoxys-ii | aes-gcm-siv
  -h, --help                    Print help
  -V, --version                 Print version
```

---

## GUI Usage

1. **Drag and drop** files onto the window.
2. Cryptyrust auto-detects the mode:
   - All files are `.arsn` → **Decrypt** mode
   - All files are plaintext → **Encrypt** mode
   - Mixed selection → a warning is shown; resolve it before proceeding
3. Click **Encrypt** or **Decrypt**, enter your password (confirm on encryption).
4. To **change the password** of a single `.arsn` file, select it alone and click *Change password*.

### Algorithm configuration

Open the **Config** menu to independently configure (for encryption only):

| Setting | Options | Default |
|---|---|---|
| **Argon2id strength** | Interactive (256 MB) · Sensitive (1 GB) | Interactive |
| **Header cipher** | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| **Payload cipher** | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| **Compression** | zstd level 3 | Disabled |

The status bar at the bottom of the window always shows the active configuration. All settings are persisted between sessions.

Click **⏱ Benchmark ciphers…** at the bottom of the Config menu to measure AEAD throughput on the current machine. The window shows encrypt and decrypt speeds for each cipher and offers an **Apply fastest combination** button. See the note below on what the benchmark actually measures.

---

## Cryptographic Design

### Key hierarchy

```
Password ──Argon2id(tiny: t=1, m=8MB)──► PreKey → HeaderMAC (HMAC-SHA256)
         │                                         verifies header integrity
         │                                         before spending memory
         │
         └──Argon2id(full: t=4, m=256MB)──► KEK (32 bytes)
                                              │
                       ┌──────────────────────┘
                       │  AEAD_hdr_cipher(KEK, kek_nonce)
                       ▼
                   WrappedDEK (48 bytes) ── keyslot, only part changed on rekey
                       │
                       │  decrypt → DEK (32 random bytes)
                       │
           ┌───────────┼──────────────────────────────────┐
           │           │                                   │
           ▼           ▼                                   ▼
    MetaKey =    BlockKey_N =                       BlockNonce_N =
  BLAKE3_derive  BLAKE3_keyed_hash                 BLAKE3_derive_key
  ("Metadata Key", DEK)  (DEK, u64_LE(N))         ("Block Nonce",
           │                  │                   file_base_nonce‖u64_LE(N))
           │                  └─────────────┬─────────────┘
           ▼                                ▼
    ProtectedMetadata           EncBlock_N = PayloadCipher(
    (Merkle root,                   key=BlockKey_N,
     sizes, metadata)               nonce=BlockNonce_N,
                                    aad=u64_LE(N),
                                    msg=plaintext_N)
```

### LUKS-style rekey

The DEK is random and lives in a dedicated 48-byte keyslot (WrappedDEK). All metadata (Merkle root, file sizes, optional fields) lives in ProtectedMetadata, encrypted under MetaKey = f(DEK). Because MetaKey depends on the DEK — not on the password — rekey only touches the 48-byte keyslot. ProtectedMetadata bytes are copied unchanged.

### Pre-authentication

Before running the expensive Argon2id derivation, Cryptyrust verifies a HeaderMAC to reject wrong passwords and forged headers quickly:

```
PreKey    = Argon2id(password, salt, t=1, m=8 192 KB, p=1)   ← ~2 ms
HeaderMAC = HMAC-SHA256(PreKey, header[0x00..0x4C])
```

Using a tiny Argon2id (rather than a raw HMAC over the password) ensures the MAC cannot serve as a fast offline brute-force oracle. A raw HMAC could be verified at ~20 billion attempts/second on a GPU; the tiny Argon2id limits this to ~15 000/s — a ×1 300 000 improvement.

### Integrity — BLAKE3 Merkle tree v1

Each encrypted block (including its AEAD tag) is hashed with domain-separated BLAKE3:

```
Leaf_N     = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1",  EncBlock_N)
Node(L, R) = BLAKE3_derive_key("Arsenic V1 Merkle Node v1",  L ‖ R)
```

Domain separation prevents second-preimage attacks where a crafted block could be confused with an internal node hash. After parallel decryption, the Merkle root is recomputed and compared to the root stored in ProtectedMetadata. **No plaintext is written until the entire file passes verification.**

### Supported ciphers

All three supported ciphers provide authenticated encryption with a 16-byte tag. The cipher IDs are stored in the header and are covered by the `HeaderMAC`.

| ID     | Algorithm              | Nonce   | Notes                                |
|--------|------------------------|---------|--------------------------------------|
| `0x02` | **Deoxys-II-256**      | 120-bit | Tweakable-block-cipher AEAD; default header cipher |
| `0x03` | **XChaCha20-Poly1305** | 192-bit | Default payload; software-friendly   |
| `0x04` | **AES-256-GCM-SIV**    | 96-bit  | Nonce-misuse resistant               |

**Performance note — header vs payload cipher:** the header cipher encrypts only **32 bytes** (the DEK in the WrappedDEK keyslot), regardless of file size. This operation takes nanoseconds and its choice has no measurable impact on throughput. The **payload cipher** processes the entire file content in 4–32 MiB blocks and is the sole determinant of encryption speed. The cipher benchmark therefore measures payload cipher throughput only and recommends the same cipher for both roles.

### Argon2id strength presets

| Preset             | t   | m          | p | Typical time |
|--------------------|-----|------------|---|--------------|
| Interactive *(default)* | 4 | 256 MiB | 4 | ~1–3 s  |
| Sensitive          | 12  | 1 GiB      | 4 | ~10–30 s     |

### Algorithms summary

| Role                         | Algorithm                                        |
|------------------------------|--------------------------------------------------|
| Pre-auth key derivation      | Argon2id (t=1, m=8 MB, p=1)                     |
| Header MAC                   | HMAC-SHA256                                      |
| Full key derivation (KEK)    | Argon2id (configurable strength)                 |
| DEK keyslot encryption       | Header cipher (Deoxys-II-256 / AES-GCM-SIV / XChaCha20) |
| Metadata encryption          | Header cipher, key = BLAKE3_derive_key(DEK)      |
| Payload block encryption     | Payload cipher (XChaCha20 / AES-GCM-SIV / Deoxys-II-256) |
| Per-block key derivation     | BLAKE3 keyed hash                                |
| Per-block nonce derivation   | BLAKE3 derive\_key                               |
| Optional compression         | zstd level 3, per-block                          |
| File integrity (Merkle)      | BLAKE3 derive\_key (domain-separated)            |
| Key material erasure         | `Secret<T>` (zeroize on drop)                   |

For the complete byte-level format specification, see [FORMAT.md](FORMAT.md) and [arsenic_V1.html](arsenic_V1.html).

---

## C / C++ FFI

The `ffi` crate exposes the entire `cryptyrust_core` API as a plain C interface suitable for linking from any language with C FFI support (C++, Qt, Python via ctypes, etc.).

### Crate layout

| Crate | Output | Description |
|---|---|---|
| `cryptyrust_ffi` | `libcryptyrust_ffi.so` / `.a` / `.dll` | C-compatible shared and static libraries |
| `ffi_test/` | `arsenic_test` binary | Minimal C++ CLI demo (encrypt / decrypt / bench) |

### Building the libraries

```bash
cargo build --release -p cryptyrust_ffi
# → target/release/libcryptyrust_ffi.so   (Linux shared library)
# → target/release/libcryptyrust_ffi.a    (static archive, embeds Rust runtime)
# → target/release/cryptyrust_ffi.dll     (Windows DLL)
```

### Generating the C header

Requires [`cbindgen`](https://github.com/mozilla/cbindgen):

```bash
cargo install cbindgen
cbindgen --config ffi/cbindgen.toml --crate cryptyrust_ffi --output cryptyrust.h
```

The header is also pre-generated at [`ffi_test/cryptyrust.h`](ffi_test/cryptyrust.h).
It includes `extern "C"` guards and is ready to include from C++ without modification.

### C API reference

#### Types

```c
// Binary buffer returned by Rust — free with arsenic_free_buffer().
typedef struct ArsBuffer { uint8_t *ptr; size_t len; } ArsBuffer;

// Encryption parameters — fill manually or use arsenic_default_params().
typedef struct ArsParams {
    uint8_t hdr_cipher;   // 0x02 Deoxys-II-256 · 0x03 XChaCha20 · 0x04 AES-GCM-SIV
    uint8_t pld_cipher;
    uint8_t strength;     // 0 = Interactive (256 MiB) · 1 = Sensitive (1 GiB)
    uint8_t compress;     // 0 = none · 1 = zstd level 3
} ArsParams;

// Optional progress callback — percentage ∈ [0, 100], user_data forwarded as-is.
typedef void (*ArsProgressFn)(int32_t percentage, void *user_data);
```

#### Error codes

| Constant | Value | Meaning |
|---|---|---|
| `ARSENIC_OK` | 0 | Success |
| `ARSENIC_ERR_DECRYPT` | -1 | Wrong password or corrupted data |
| `ARSENIC_ERR_IO` | -2 | File I/O error |
| `ARSENIC_ERR_PARAMS` | -3 | Invalid cipher ID or strength |
| `ARSENIC_ERR_BAD_MAGIC` | -4 | Not an Arsenic V1 file |
| `ARSENIC_ERR_NULL_PTR` | -5 | Required pointer was null |

Call `arsenic_last_error()` after any failure for a human-readable UTF-8 string.
The pointer is valid until the next `arsenic_*` call on the same thread.

#### Functions

```c
// Default params: Deoxys-II-256 header · XChaCha20-Poly1305 payload · Interactive · no compression
ArsParams arsenic_default_params(void);

// Encrypt/decrypt in-memory buffers. Cipher params for decrypt come from the file header.
int32_t arsenic_encrypt(const uint8_t *pt, size_t pt_len,
                        const char *password, const ArsParams *params,
                        ArsProgressFn cb, void *user_data,
                        ArsBuffer *out);

int32_t arsenic_decrypt(const uint8_t *ct, size_t ct_len,
                        const char *password,
                        ArsProgressFn cb, void *user_data,
                        ArsBuffer *out);

// Change the password of a .arsn file in-place (crash-safe).
int32_t arsenic_rekey_file(const char *path,
                           const char *old_pw, const char *new_pw,
                           ArsProgressFn cb, void *user_data);

// 1 if the file starts with the Arsenic V1 magic, 0 otherwise.
int32_t arsenic_is_arsenic_file(const char *path);

// Free a buffer allocated by arsenic_encrypt / arsenic_decrypt. Safe to call with null.
void arsenic_free_buffer(ArsBuffer *buf);

// Benchmark the 3 AEAD ciphers. Returns an array sorted fastest-first.
ArsBenchArray arsenic_bench(size_t payload_mib);          // 32 is a good default
void          arsenic_free_bench_array(ArsBenchArray arr);
void          arsenic_bench_best_combo(const ArsBenchArray *arr,
                                       uint8_t *hdr_out, uint8_t *pld_out);

// Thread-local last error (valid until next arsenic_* call on this thread).
const char *arsenic_last_error(void);
```

> **Progress note:** the progress callback fires between 0 % and 100 % *after* the Argon2id key derivation completes. For Interactive strength, expect ~2 s of silence before the bar moves — this is the KDF, not a hang.

> **Benchmark note:** only the **payload cipher** is benchmarked on large data. The header cipher processes only 32 bytes (the DEK) — its choice has no measurable effect on throughput. `arsenic_bench_best_combo` therefore recommends the same fastest cipher for both `hdr_cipher` and `pld_cipher`.

### Using in a CMake / Qt project

#### 1. Static linking (simplest)

```cmake
# In your CMakeLists.txt
target_include_directories(MyTarget PRIVATE /path/to/cryptyrust.h)
target_link_libraries(MyTarget PRIVATE
    /path/to/libcryptyrust_ffi.a
    pthread dl m          # Linux — not needed on macOS / Windows
)
```

#### 2. With Corrosion (builds Rust automatically)

[Corrosion](https://github.com/corrosion-rs/corrosion) integrates Rust crates as native CMake targets:

```cmake
find_package(Corrosion REQUIRED)

corrosion_import_crate(
    MANIFEST_PATH /path/to/cryptyrust/Cargo.toml
    CRATES cryptyrust_ffi
)

target_link_libraries(MyTarget PRIVATE cryptyrust_ffi)
target_include_directories(MyTarget PRIVATE /path/to/ffi_test)  # cryptyrust.h
```

#### 3. Qt progress bar — minimal pattern

```cpp
#include "cryptyrust.h"
#include <QProgressDialog>

struct ProgressCtx { QProgressDialog* dlg; };

static void on_progress(int32_t pct, void* ud) {
    auto* ctx = static_cast<ProgressCtx*>(ud);
    ctx->dlg->setValue(pct);
    QCoreApplication::processEvents();   // keep UI responsive
}

// In your slot:
QProgressDialog dlg("Encrypting…", QString(), 0, 100, this);
dlg.setWindowModality(Qt::WindowModal);
dlg.show();

ProgressCtx ctx{&dlg};
ArsParams params = arsenic_default_params();
ArsBuffer out{};

int32_t rc = arsenic_encrypt(
    data.constData(), data.size(),
    password.toUtf8().constData(), &params,
    on_progress, &ctx,
    &out
);

if (rc != ARSENIC_OK) {
    QMessageBox::critical(this, "Error", arsenic_last_error());
} else {
    QByteArray ciphertext(reinterpret_cast<char*>(out.ptr), out.len);
    arsenic_free_buffer(&out);
}
```

### Running the C++ demo

The `ffi_test/` directory contains a self-contained CMake project:

```bash
cd ffi_test
cmake -S . -B build         # -DBUILD_RUST=ON (default) runs cargo automatically
cmake --build build

./build/arsenic_test encrypt  secret.pdf    "my passphrase"
./build/arsenic_test decrypt  secret.pdf.arsn  "my passphrase"
./build/arsenic_test bench    32
```

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
