# arsenic_ffi

C-compatible FFI layer for the `arsenic` library. Exposes all encryption, key management and benchmark operations through a stable C interface.

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
| `ARSENIC_ERR_DECRYPT` | -1 | Wrong password or corrupted data |
| `ARSENIC_ERR_IO` | -2 | I/O error |
| `ARSENIC_ERR_PARAMS` | -3 | Invalid parameter |
| `ARSENIC_ERR_BAD_MAGIC` | -4 | Not a valid Arsenic file |
| `ARSENIC_ERR_NULL_PTR` | -5 | Unexpected null pointer |
| `ARSENIC_ERR_CANCELLED` | -6 | Operation cancelled |
| `ARSENIC_ERR_NO_ASYM_KEY` | -7 | No keyslot matches the supplied key |

On error, `arsenic_last_error()` returns a descriptive message.

### Main types

```c
// Encryption parameters
typedef struct { uint8_t hdr_cipher; uint8_t pld_cipher; uint8_t strength; } ArsParams;

// Memory buffer (must be freed with arsenic_free_buffer)
typedef struct { uint8_t *ptr; size_t len; } ArsBuffer;

// Array of ephemeral public keys (must be freed with arsenic_free_pubkey_array)
typedef struct { uint8_t *data; size_t count; } ArsPubKeyArray;  // count × 32 bytes

// Benchmark results (must be freed with arsenic_free_bench_array)
typedef struct { uint8_t cipher_id; double encrypt_mibps; double decrypt_mibps; } ArsBenchResult;
typedef struct { ArsBenchResult *results; size_t count; } ArsBenchArray;
```

### Hybrid recipients

Each recipient is represented by **1 216 bytes**: `x25519_pk[32] || mlkem_768_ek[1184]`.
This format is used for both ML-KEM-768 and ML-KEM-1024 keyslots; the `ArsParams`
`kem_level` field selects which level is used during encryption.

> **Note:** The FFI functions accept a 32-byte private key and derive the ML-KEM
> seed via BLAKE3 internally (legacy behavior). Applications that generate new
> keys should use `arsenic_generate_keypair` and store the 32-byte result; the
> ML-KEM seed is derived automatically on each use.

Derive the hybrid public key from a private key:
```c
uint8_t priv[32];  // 32-byte private key (seed)
uint8_t hybrid_pub[1216];
arsenic_hybrid_pubkey(priv, hybrid_pub);  // x25519_pk[32] || mlkem_768_ek[1184]
```

### In-memory encrypt / decrypt

```c
ArsBuffer ct = {0};
ArsParams p = arsenic_default_params();
// recipients: flat array of n × 1216 bytes
int rc = arsenic_encrypt(plain, plain_len, "password", &p,
                          recipients, n_recipients, NULL, NULL, &ct);
arsenic_free_buffer(&ct);

ArsBuffer pt = {0};
rc = arsenic_decrypt(ct.ptr, ct.len, "password", NULL, NULL, &pt);
arsenic_free_buffer(&pt);

// Asymmetric decryption
rc = arsenic_decrypt_with_key(ct.ptr, ct.len, priv_key_32, NULL, NULL, &pt);
```

### File encrypt / decrypt

```c
rc = arsenic_encrypt_file("in.txt", "in.txt.arsn", "password", &p,
                           recipients, n_recipients, NULL, NULL);
rc = arsenic_decrypt_file("in.txt.arsn", "out.txt", "password", NULL, NULL);
rc = arsenic_decrypt_file_with_key("in.txt.arsn", "out.txt", priv_key_32, NULL, NULL);
```

### Keyslot management

```c
// Add a hybrid recipient (1216 bytes)
rc = arsenic_add_recipient_file("file.arsn", "password", hybrid_pub_1216, NULL, NULL);

// Remove by index
rc = arsenic_remove_recipient_file("file.arsn", "password", 0, NULL, NULL);

// List ephemeral public keys
ArsPubKeyArray arr = arsenic_list_recipients_file("file.arsn");
// arr.count keyslots, arr.data = count × 32 bytes
arsenic_free_pubkey_array(&arr);

// Find which private key can decrypt a file
// privkeys: flat array of n × 32 bytes
int idx = arsenic_find_matching_key_file("file.arsn", privkeys, n_keys);
// returns 0-based index or -1
```

### Key utilities

```c
// Generate an X25519 keypair
uint8_t priv[32], pub[32];
arsenic_generate_keypair(priv, pub);

// Derive the full hybrid public key (1216 bytes) from a private key
uint8_t hybrid[1216];
arsenic_hybrid_pubkey(priv, hybrid);

// Bech32 encoding
char buf[128];
arsenic_encode_pubkey(pub, buf, sizeof(buf));      // arsenic1...  (60 chars)
arsenic_encode_privkey(priv, buf, sizeof(buf));    // ARSENIC-SECRET-KEY-1...  (72 chars)

// Decoding
uint8_t decoded[32];
int ok = arsenic_decode_pubkey("arsenic1...", decoded);
```

### Benchmark

```c
ArsBenchArray arr = arsenic_bench(32);  // 32 MiB, sorted fastest-first
uint8_t best_hdr, best_pld;
arsenic_bench_best_combo(&arr, &best_hdr, &best_pld);
arsenic_free_bench_array(arr);
```

---

## Memory Safety

All functions returning an `ArsBuffer` or `ArsPubKeyArray` transfer ownership to the caller. These buffers **must** be freed with `arsenic_free_buffer` / `arsenic_free_pubkey_array` exactly once.

The last error message is stored in a `thread_local` — it is valid until the next `arsenic_*` call on that thread.

---

## Tests

```bash
cargo test -p arsenic_ffi
# 21 tests covering: symmetric and asymmetric memory and file round-trips,
# rekey, add/list/remove recipients, find_matching_key, key encode/decode, benchmark
```
