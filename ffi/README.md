# arsenic_ffi

C-compatible FFI layer for the `arsenic` library. Exposes the full API — encryption, decryption, ASCII armor, zstd compression, passphrase slot management, partial block access, recipient management, key utilities and benchmarks — through a stable C interface.

Outputs: `libarsenic_ffi.so` (Linux), `libarsenic_ffi.dylib` (macOS), `arsenic_ffi.dll` (Windows), and the static archive `.a` / `.lib`.

---

## Building

```bash
cargo build --release -p arsenic_ffi
# → target/release/libarsenic_ffi.so  (Linux)
# → target/release/libarsenic_ffi.a
```

### Generate the C header

```bash
cargo install cbindgen
cbindgen --config ffi/cbindgen.toml --crate arsenic_ffi --output arsenic.h
```

---

## API — Overview

### Return codes

| Code | Value | Description |
|---|---|---|
| `ARSENIC_OK` | 0 | Success |
| `ARSENIC_ERR_DECRYPT` | -1 | Wrong password, corrupted data, or AEAD failure |
| `ARSENIC_ERR_IO` | -2 | I/O error (file not found, permission denied…) |
| `ARSENIC_ERR_PARAMS` | -3 | Invalid parameter (unknown cipher, strength, level…) |
| `ARSENIC_ERR_BAD_MAGIC` | -4 | Not a valid Arsenic file / no sender info present |
| `ARSENIC_ERR_NULL_PTR` | -5 | Unexpected null pointer |
| `ARSENIC_ERR_CANCELLED` | -6 | Operation cancelled via progress callback |
| `ARSENIC_ERR_NO_ASYM_KEY` | -7 | No keyslot matches the supplied private key |

On error, `arsenic_last_error()` returns a descriptive UTF-8 string (valid until the next `arsenic_*` call on this thread).

---

### Main types

```c
// Encryption parameters — pass to arsenic_encrypt / arsenic_encrypt_file.
typedef struct {
    uint8_t hdr_cipher;      // 0x02=Deoxys-II (default) 0x03=XChaCha20 0x04=AES-GCM-SIV
    uint8_t pld_cipher;      // same set of IDs, independently chosen
    uint8_t strength;        // 0=Interactive (256 MiB) 1=Sensitive (1 GiB)
    int8_t  compress_level;  // 0=no compression, 1-22=zstd level (3 is a good default)
                             // WARNING: compression leaks plaintext entropy via size!
} ArsParams;

// Heap-allocated byte buffer — free with arsenic_free_buffer().
typedef struct { uint8_t *ptr; size_t len; } ArsBuffer;

// Flat array of X25519 ephemeral public keys — free with arsenic_free_pubkey_array().
typedef struct { uint8_t *data; size_t count; } ArsPubKeyArray;  // count × 32 bytes

// Benchmark results — free with arsenic_free_bench_array().
typedef struct { uint8_t cipher_id; double encrypt_mibps; double decrypt_mibps; } ArsBenchResult;
typedef struct { ArsBenchResult *results; size_t count; } ArsBenchArray;
```

### Default parameters

```c
ArsParams p = arsenic_default_params();
// → { hdr_cipher=0x02, pld_cipher=0x03, strength=0, compress_level=0 }
```

---

## In-memory Encrypt / Decrypt

```c
// Symmetric (password)
ArsBuffer ct = {0};
ArsParams p = arsenic_default_params();
int rc = arsenic_encrypt(plain, plain_len, "password", &p,
                          NULL, 0,  // no recipients
                          NULL, NULL, &ct);
arsenic_free_buffer(&ct);

ArsBuffer pt = {0};
rc = arsenic_decrypt(ct.ptr, ct.len, "password", NULL, NULL, &pt);
arsenic_free_buffer(&pt);

// Asymmetric (hybrid X25519 + ML-KEM-768 private key, 32 bytes)
rc = arsenic_decrypt_with_key(ct.ptr, ct.len, priv_key_32, NULL, NULL, &pt);
```

### With compression

```c
ArsParams p = arsenic_default_params();
p.compress_level = 3;  // zstd level 3
// WARNING: arsenic_last_error() will remind you of the size-leak risk.
rc = arsenic_encrypt(plain, plain_len, "password", &p, NULL, 0, NULL, NULL, &ct);
```

### With asymmetric recipients

```c
// Recipients: flat array of n × 1216 bytes (x25519_pk[32] || mlkem_ek[1184])
uint8_t hybrid_pub[1216];
arsenic_hybrid_pubkey(priv_key_32, hybrid_pub);  // derive from private key

rc = arsenic_encrypt(plain, plain_len, NULL, &p,
                      hybrid_pub, 1,  // 1 recipient
                      NULL, NULL, &ct);
```

---

## File Encrypt / Decrypt

```c
// Encrypt
rc = arsenic_encrypt_file("in.txt", "in.txt.arsn", "password", &p,
                           recipients, n_recipients, NULL, NULL);

// Decrypt (symmetric)
rc = arsenic_decrypt_file("in.txt.arsn", "out.txt", "password", NULL, NULL);

// Decrypt (asymmetric)
rc = arsenic_decrypt_file_with_key("in.txt.arsn", "out.txt", priv_key_32, NULL, NULL);
```

---

## ASCII Armor

Armor wraps the binary `.arsn` ciphertext in base64 for text-safe transport (email, config files, copy-paste). **Armor reveals the exact ciphertext length** (leaks plaintext size lower bound).

```c
// Armor: binary → text
ArsBuffer armored = {0};
rc = arsenic_armor(ct.ptr, ct.len, &armored);
// armored.ptr → "-----BEGIN ARSENIC ENCRYPTED FILE-----\n..."
printf("%.*s", (int)armored.len, (char*)armored.ptr);
arsenic_free_buffer(&armored);

// Dearmor: text → binary
ArsBuffer binary = {0};
rc = arsenic_dearmor("-----BEGIN ARSENIC ENCRYPTED FILE-----\n...", &binary);
arsenic_free_buffer(&binary);
```

---

## Partial / Random-Access Block Decryption

Decrypt a single block by index without reading the rest of the file.

**Security contract:** only the block's AEAD tag is verified — the Merkle root is **not** checked. Protects against per-block corruption/forgery but not against file truncation or inter-file block substitution. Do not use for security-critical decisions; use full `arsenic_decrypt` instead.

Returns `ARSENIC_ERR_PARAMS` if the file was encrypted with compression (compressed files do not support random access).

```c
// Symmetric path
ArsBuffer block = {0};
rc = arsenic_decrypt_block(ct.ptr, ct.len, "password", 0 /* block index */,
                            NULL, NULL, &block);
arsenic_free_buffer(&block);

// Asymmetric path
rc = arsenic_decrypt_block_with_key(ct.ptr, ct.len, priv_key_32, 42,
                                     NULL, NULL, &block);
arsenic_free_buffer(&block);
```

---

## Passphrase Slot Management

Up to 15 extra passphrase slots can be added to any file. Any slot (primary or extra) can decrypt the file.

**Note:** the primary slot benefits from a HeaderMAC fast-fail — wrong passwords are detected before Argon2id. Extra slots have no HeaderMAC; wrong passwords pay the full Argon2id cost per slot.

```c
// Count extra slots (no password required — count is in the public header)
int n = arsenic_passphrase_count_file("file.arsn");
// n = 0 means only the primary slot exists; n = -1 means error.

// Add an extra passphrase slot
rc = arsenic_add_passphrase_file("file.arsn", "existing_pw", "new_pw", NULL, NULL);

// Remove an extra passphrase slot (primary password required for HeaderMAC)
rc = arsenic_remove_passphrase_file("file.arsn", "primary_pw", "pw_to_remove", NULL, NULL);
```

---

## Keyslot (Recipient) Management

```c
// List all asymmetric keyslots (returns ephemeral X25519 keys, not recipients' own keys)
ArsPubKeyArray arr = arsenic_list_recipients_file("file.arsn");
printf("%zu recipient(s)\n", arr.count);
arsenic_free_pubkey_array(&arr);

// Add a recipient keyslot (requires symmetric password)
rc = arsenic_add_recipient_file("file.arsn", "password", hybrid_pub_1216, NULL, NULL);

// Remove a keyslot by 0-based index (requires symmetric password)
rc = arsenic_remove_recipient_file("file.arsn", "password", 0, NULL, NULL);

// Find which private key (from a flat array) can decrypt the file
// Returns 0-based index of the matching key, or -1.
int idx = arsenic_find_matching_key_file("file.arsn", privkeys_flat, n_keys);

// Find which keyslot index a private key unlocks (for remove_recipient)
int slot = arsenic_find_slot_for_key_file("file.arsn", priv_key_32);
```

---

## Password Change (Rekey)

Changes the primary password without re-encrypting the payload. O(1) regardless of file size.

```c
rc = arsenic_rekey_file("file.arsn", "old_password", "new_password", NULL, NULL);
```

---

## Sender Identity

The sender region is stored unencrypted in the header and readable without a password.

```c
char name[256];
uint8_t x25519_pk[32], mlkem_pk[1184];
rc = arsenic_read_sender_info_file("file.arsn",
                                    name, sizeof(name),
                                    x25519_pk, mlkem_pk);
if (rc == ARSENIC_OK) {
    printf("Sender: %s\n", name);
}
// ARSENIC_ERR_BAD_MAGIC = no sender info in this file
```

---

## Key Utilities

```c
// Generate an X25519 keypair
uint8_t priv[32], pub[32];
arsenic_generate_keypair(priv, pub);

// Derive X25519 public key from private key
arsenic_pubkey_from_privkey(priv, pub);

// Derive the 1216-byte hybrid public key (x25519[32] || mlkem_ek[1184])
uint8_t hybrid[1216];
arsenic_hybrid_pubkey(priv, hybrid);

// Bech32 encoding / decoding
char buf[128];
arsenic_encode_pubkey(pub, buf, sizeof(buf));     // "arsenic1..."  (60 chars)
arsenic_encode_privkey(priv, buf, sizeof(buf));   // "ARSENIC-SECRET-KEY-1..."  (72 chars)

uint8_t decoded[32];
int ok = arsenic_decode_pubkey("arsenic1...", decoded);
int ok2 = arsenic_decode_privkey("ARSENIC-SECRET-KEY-1...", decoded);

// ML-KEM-768 encapsulation key (1184 bytes)
uint8_t ek[1184];
arsenic_encode_mlkem_pubkey(ek, buf, 1956);       // "arsenic1m..."
int ok3 = arsenic_decode_mlkem_pubkey("arsenic1m...", ek);
```

---

## Benchmark

```c
ArsBenchArray arr = arsenic_bench(32);  // 32 MiB payload, sorted fastest-first
printf("Fastest cipher: 0x%02x (%.0f MiB/s encrypt)\n",
       arr.results[0].cipher_id, arr.results[0].encrypt_mibps);

uint8_t best_hdr, best_pld;
arsenic_bench_best_combo(&arr, &best_hdr, &best_pld);
arsenic_free_bench_array(arr);
```

---

## File Detection

```c
int is_arsn = arsenic_is_arsenic_file("file.arsn");  // 1 = yes, 0 = no
ArsKdfParams kdf;
rc = arsenic_read_params_file("file.arsn", &kdf);
// kdf.t_cost, kdf.m_cost_kib, kdf.p_cost, kdf.hdr_cipher, kdf.pld_cipher
```

---

## Memory Safety

- All functions returning `ArsBuffer` or `ArsPubKeyArray` transfer ownership to the caller. Free exactly once with `arsenic_free_buffer` / `arsenic_free_pubkey_array`.
- `arsenic_free_bench_array` frees `ArsBenchArray`.
- The last error string is `thread_local` — valid until the next `arsenic_*` call on that thread.

---

## Tests

```bash
cargo test -p arsenic_ffi
# 21 tests: symmetric/asymmetric memory and file round-trips,
# rekey, add/list/remove recipients, find_matching_key,
# key encode/decode, benchmark
```
