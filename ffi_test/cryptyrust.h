#ifndef CRYPTYRUST_H
#define CRYPTYRUST_H

/* Hand-maintained C header for arsenic_ffi.
 * Keep in sync with ffi/src/lib.rs when the API changes.
 * To regenerate automatically: cbindgen --config ffi/cbindgen.toml --crate arsenic_ffi
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* ── Error codes ─────────────────────────────────────────────────────────── */

/** Operation succeeded. */
#define ARSENIC_OK              0
/** Wrong password, corrupted data, or AEAD authentication failure. */
#define ARSENIC_ERR_DECRYPT    -1
/** I/O error (file not found, permission denied, etc.). */
#define ARSENIC_ERR_IO         -2
/** Invalid parameter (unknown cipher ID, strength value, etc.). */
#define ARSENIC_ERR_PARAMS     -3
/** File does not carry Arsenic magic bytes or has a bad version. */
#define ARSENIC_ERR_BAD_MAGIC  -4
/** A required pointer argument was null. */
#define ARSENIC_ERR_NULL_PTR   -5
/** Operation was cancelled by the caller via the progress callback. */
#define ARSENIC_ERR_CANCELLED  -6
/** No asymmetric keyslot matched the provided private key. */
#define ARSENIC_ERR_NO_ASYM_KEY -7
/** Unclassified error — call arsenic_last_error() for details. */
#define ARSENIC_ERR_UNKNOWN   -99

/* ── Types ───────────────────────────────────────────────────────────────── */

/**
 * Heap-allocated byte buffer returned by arsenic_encrypt / arsenic_decrypt.
 * Must be released with arsenic_free_buffer exactly once.
 * ptr is null and len is 0 on error.
 */
typedef struct ArsBuffer {
    uint8_t  *ptr;
    uintptr_t len;
} ArsBuffer;

/**
 * Flat array of X25519 ephemeral public keys (32 bytes each) returned by
 * arsenic_list_recipients_file.  Free with arsenic_free_pubkey_array.
 * data = count × 32 bytes, tightly packed.
 */
typedef struct ArsPubKeyArray {
    uint8_t  *data;
    uintptr_t count;
} ArsPubKeyArray;

/**
 * Encryption parameters.
 *
 * Cipher IDs (header byte value):
 *   0x02  Deoxys-II-256            (default header cipher)
 *   0x03  XChaCha20-Poly1305       (default payload cipher)
 *   0x04  AES-256-GCM-SIV
 *
 * strength:
 *   0  Interactive  (256 MiB, ~1–3 s)
 *   1  Sensitive    (1 GiB,  ~10–30 s)
 */
typedef struct ArsParams {
    uint8_t hdr_cipher;
    uint8_t pld_cipher;
    uint8_t strength;
} ArsParams;

/**
 * Argon2id / cipher parameters read from an existing Arsenic file header
 * by arsenic_read_params_file.
 */
typedef struct ArsKdfParams {
    uint32_t t_cost;
    uint32_t m_cost_kib;
    uint32_t p_cost;
    uint8_t  hdr_cipher;
    uint8_t  pld_cipher;
} ArsKdfParams;

/**
 * Optional progress callback.  percentage is 0–100.
 * user_data is whatever pointer the caller passed alongside the callback.
 * Pass NULL to ignore progress.
 */
typedef void (*ArsProgressFn)(int32_t percentage, void *user_data);

/** Benchmark result for one AEAD cipher. */
typedef struct ArsBenchResult {
    /** Cipher byte ID: 0x02 Deoxys-II · 0x03 XChaCha20 · 0x04 AES-GCM-SIV. */
    uint8_t cipher_id;
    double  encrypt_mibps;
    double  decrypt_mibps;
} ArsBenchResult;

/**
 * Array of benchmark results (sorted fastest-first).
 * Free with arsenic_free_bench_array.
 */
typedef struct ArsBenchArray {
    ArsBenchResult *results;
    uintptr_t       count;
} ArsBenchArray;

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error reporting ─────────────────────────────────────────────────────── */

/**
 * Return the last error message (null-terminated UTF-8) for this thread.
 * Valid until the next arsenic_* call on this thread.  Returns NULL if no
 * error has occurred yet.
 */
const char *arsenic_last_error(void);

/**
 * Library version string (e.g. "1.3.2").
 * The pointer is valid for the lifetime of the process.
 */
const char *arsenic_version(void);

/* ── Memory management ───────────────────────────────────────────────────── */

/** Free a buffer returned by any arsenic_* in-memory function. */
void arsenic_free_buffer(ArsBuffer *buf);

/** Free an ArsPubKeyArray returned by arsenic_list_recipients_file. */
void arsenic_free_pubkey_array(ArsPubKeyArray *arr);

/* ── Parameters ──────────────────────────────────────────────────────────── */

/** Returns default parameters: Deoxys-II-256 header · XChaCha20 payload · Interactive. */
ArsParams arsenic_default_params(void);

/**
 * Read Argon2id and cipher parameters from an existing Arsenic file header.
 * Returns ARSENIC_OK on success and fills *out.
 * Returns ARSENIC_ERR_BAD_MAGIC if the file is not a valid Arsenic file.
 */
int32_t arsenic_read_params_file(const char *path, ArsKdfParams *out);

/* ── In-memory encrypt / decrypt ─────────────────────────────────────────── */

/**
 * Encrypt a plaintext buffer in memory.
 *
 * recipients is a flat array of n_recipients × 1216 bytes
 * (x25519_pk[32] || mlkem_ek[1184] per recipient).
 * Pass NULL / 0 for symmetric-only encryption.
 * If n_recipients > 0 and password is NULL or empty, a random KEK is used.
 *
 * On success writes ciphertext to *out; call arsenic_free_buffer when done.
 */
int32_t arsenic_encrypt(const uint8_t     *plaintext,
                        uintptr_t          plaintext_len,
                        const char        *password,
                        const ArsParams   *params,
                        const uint8_t     *recipients,
                        uintptr_t          n_recipients,
                        ArsProgressFn      progress_fn,
                        void              *user_data,
                        ArsBuffer         *out);

/**
 * Decrypt a ciphertext buffer in memory using a password.
 * Cipher parameters are read from the file header — no ArsParams needed.
 */
int32_t arsenic_decrypt(const uint8_t *ciphertext,
                        uintptr_t      ciphertext_len,
                        const char    *password,
                        ArsProgressFn  progress_fn,
                        void          *user_data,
                        ArsBuffer     *out);

/**
 * Decrypt a ciphertext buffer in memory using a 32-byte X25519 private key.
 * Returns ARSENIC_ERR_NO_ASYM_KEY if the key does not match any keyslot.
 *
 * privkey must point to exactly 32 readable bytes.
 */
int32_t arsenic_decrypt_with_key(const uint8_t *ciphertext,
                                 uintptr_t      ciphertext_len,
                                 const uint8_t *privkey,
                                 ArsProgressFn  progress_fn,
                                 void          *user_data,
                                 ArsBuffer     *out);

/* ── File-based encrypt / decrypt ────────────────────────────────────────── */

/**
 * Encrypt a file, writing the result to path_out.
 * recipients / n_recipients: same semantics as arsenic_encrypt.
 */
int32_t arsenic_encrypt_file(const char     *path_in,
                             const char     *path_out,
                             const char     *password,
                             const ArsParams *params,
                             const uint8_t  *recipients,
                             uintptr_t       n_recipients,
                             ArsProgressFn   progress_fn,
                             void           *user_data);

/** Decrypt an Arsenic file using a password, writing plaintext to path_out. */
int32_t arsenic_decrypt_file(const char    *path_in,
                             const char    *path_out,
                             const char    *password,
                             ArsProgressFn  progress_fn,
                             void          *user_data);

/**
 * Decrypt an Arsenic file using a 32-byte X25519 private key.
 * Returns ARSENIC_ERR_NO_ASYM_KEY if the key does not match any keyslot.
 *
 * privkey must point to exactly 32 readable bytes.
 */
int32_t arsenic_decrypt_file_with_key(const char    *path_in,
                                     const char    *path_out,
                                     const uint8_t *privkey,
                                     ArsProgressFn  progress_fn,
                                     void          *user_data);

/* ── Rekey ───────────────────────────────────────────────────────────────── */

/**
 * Change the password of an Arsenic file in-place.
 * Only the 48-byte symmetric keyslot is rewritten; the payload is untouched.
 * A crash-safe .bak backup is written before the in-place write.
 */
int32_t arsenic_rekey_file(const char    *path,
                           const char    *old_password,
                           const char    *new_password,
                           ArsProgressFn  progress_fn,
                           void          *user_data);

/* ── File detection ──────────────────────────────────────────────────────── */

/** Returns 1 if the file begins with Arsenic magic bytes, 0 otherwise. */
int32_t arsenic_is_arsenic_file(const char *path);

/* ── Recipient management ────────────────────────────────────────────────── */

/**
 * List the ephemeral X25519 public keys of all hybrid keyslots in a file.
 * The returned ArsPubKeyArray must be freed with arsenic_free_pubkey_array.
 * On error, data = NULL, count = 0; check arsenic_last_error().
 */
ArsPubKeyArray arsenic_list_recipients_file(const char *path);

/**
 * Add a hybrid (X25519 + ML-KEM-768) keyslot to a file.
 * recipient must point to 1216 bytes: x25519_pk[32] || mlkem_ek[1184].
 * Requires the symmetric password to authenticate the header.
 */
int32_t arsenic_add_recipient_file(const char    *path,
                                   const char    *password,
                                   const uint8_t *recipient,
                                   ArsProgressFn  progress_fn,
                                   void          *user_data);

/**
 * Remove the hybrid keyslot at 0-based index from a file.
 * Requires the symmetric password.
 */
int32_t arsenic_remove_recipient_file(const char    *path,
                                      const char    *password,
                                      uintptr_t      index,
                                      ArsProgressFn  progress_fn,
                                      void          *user_data);

/**
 * Find which private key (if any) can decrypt the file's hybrid keyslots.
 * privkeys is a flat array of n_keys × 32 bytes.
 * Returns the 0-based index of the first matching key, or -1 if none match.
 */
int32_t arsenic_find_matching_key_file(const char    *path,
                                       const uint8_t *privkeys,
                                       uintptr_t      n_keys);

/* ── Key utilities ───────────────────────────────────────────────────────── */

/**
 * Generate a fresh X25519 keypair.
 * privkey_out and pubkey_out must each point to 32 writable bytes.
 */
void arsenic_generate_keypair(uint8_t *privkey_out, uint8_t *pubkey_out);

/**
 * Derive the X25519 public key from a 32-byte private key.
 * privkey must point to 32 readable bytes; pubkey_out to 32 writable bytes.
 */
void arsenic_pubkey_from_privkey(const uint8_t *privkey, uint8_t *pubkey_out);

/**
 * Derive the 1216-byte hybrid public key (x25519_pk[32] || mlkem_ek[1184])
 * from a 32-byte private key.
 * privkey must point to 32 readable bytes; hybrid_out to 1216 writable bytes.
 * Use the result as a recipients element in arsenic_encrypt / arsenic_encrypt_file.
 */
void arsenic_hybrid_pubkey(const uint8_t *privkey, uint8_t *hybrid_out);

/**
 * Encode a 32-byte public key as a null-terminated arsenic1... string (60 chars).
 * buf must be at least 61 bytes.  Returns character count (excl. null) or 0.
 */
uintptr_t arsenic_encode_pubkey(const uint8_t *pubkey, char *buf, uintptr_t buf_len);

/**
 * Decode an arsenic1... string into a 32-byte public key.
 * Returns 1 on success, 0 on failure.
 */
int32_t arsenic_decode_pubkey(const char *encoded, uint8_t *pubkey_out);

/**
 * Encode a 32-byte private key as a null-terminated ARSENIC-SECRET-KEY-1... string (72 chars).
 * buf must be at least 73 bytes.  Returns character count (excl. null) or 0.
 */
uintptr_t arsenic_encode_privkey(const uint8_t *privkey, char *buf, uintptr_t buf_len);

/**
 * Decode an ARSENIC-SECRET-KEY-1... string into a 32-byte private key.
 * Returns 1 on success, 0 on failure.
 */
int32_t arsenic_decode_privkey(const char *encoded, uint8_t *privkey_out);

/* ── Benchmark ───────────────────────────────────────────────────────────── */

/**
 * Benchmark the three AEAD ciphers on payload_mib MiB of data.
 * Returns an ArsBenchArray sorted fastest-first.
 * Free with arsenic_free_bench_array.  payload_mib = 32 is a good default.
 */
ArsBenchArray arsenic_bench(uintptr_t payload_mib);

/** Free an ArsBenchArray returned by arsenic_bench. */
void arsenic_free_bench_array(ArsBenchArray arr);

/**
 * Write the recommended (hdr_cipher_id, pld_cipher_id) to *hdr_out / *pld_out.
 * arr must be sorted fastest-first (as returned by arsenic_bench).
 */
void arsenic_bench_best_combo(const ArsBenchArray *arr,
                              uint8_t             *hdr_out,
                              uint8_t             *pld_out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTYRUST_H */
