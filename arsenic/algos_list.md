# Cryptographic Algorithms Used in Arsenic

This document lists every cryptographic algorithm used in the `arsenic` library, grouped by functional role.

---

## Table of Contents

1. [Password-based Key Derivation — Argon2id](#1-argon2id)
2. [Header MAC — BLAKE3_keyed_hash](#2-blake3_keyed_hash-for-headermac)
3. [Hash Functions and Internal Derivation — BLAKE3](#3-blake3)
4. [Authenticated Ciphers (AEAD)](#4-aead-ciphers)
5. [Post-quantum Hybrid KEM](#5-post-quantum-hybrid-kem)
6. [Merkle Tree](#6-merkle-tree)
7. [Key Encoding — Bech32](#7-bech32)
8. [Compression — zstd](#8-zstd-compression)
9. [Secure Memory Erasure — Zeroize](#9-zeroize)
10. [Role Overview](#10-overview)

---

## 1. Argon2id

**Role:** derive a cryptographic key from a human password.

**Standard:** winner of the Password Hashing Competition (PHC) 2015, recommended by NIST SP 800-63B.

| Property | Argon2id | bcrypt | scrypt | PBKDF2 |
|---|---|---|---|---|
| GPU resistance | ✓✓ | ✓ | ✓✓ | ✗ |
| FPGA/ASIC resistance | ✓✓ | ✗ | ✓ | ✗ |
| Side-channel protection | ✓ | ✗ | ✗ | ✗ |
| Configurability | memory + time + parallelism | time only | memory + time | time only |

**Use in Arsenic — KEK derivation:**

| Preset | `t_cost` | `m_cost` | `p_cost` | RAM | Typical time |
|---|---|---|---|---|---|
| **Interactive** *(default)* | 4 | 262 144 KB | 4 | 256 MiB | ~1–3 s |
| **Sensitive** | 12 | 1 048 576 KB | 4 | 1 GiB | ~10–30 s |

Parameters are stored in the pre-MAC section and **shared by all passphrase slots** (primary + extra). They cannot be set per-slot.

**DoS protection:** parameters are validated against bounds before any Argon2id invocation — tampered extreme values are rejected at zero cost.

---

## 2. BLAKE3_keyed_hash for HeaderMAC

**Role:** authenticate the primary passphrase slot of the file header.

```
KEK       = Argon2id(password, salt, t_cost, m_cost, p_cost) → 32 bytes
HeaderMAC = BLAKE3_keyed_hash(key=KEK, data=pre_mac[77])     → 32 bytes
```

The HeaderMAC provides **fast-fail** for the primary slot: a wrong password is
detected before any AEAD decryption attempt. Extra passphrase slots have no
HeaderMAC — wrong passwords cost a full Argon2id call per extra slot.

---

## 3. BLAKE3

**Role:** internal sub-key derivation, nonce derivation, and Merkle tree computation.

### 3a. `blake3::keyed_hash(key, data) → [u8; 32]`

Used for per-block key derivation:
```
block_key_i = BLAKE3_keyed_hash(key=DEK, data=i.to_le_bytes())
```

### 3b. `blake3::derive_key(context, material) → [u8; 32]`

Fixed-context KDF used throughout Arsenic:

| Context string | Input | Output |
|---|---|---|
| `"Arsenic V1 Block Nonce"` | `file_base_nonce ‖ i.to_le_bytes()` | `block_nonce_i[24]` |
| `"Arsenic V1 Metadata Key"` | `DEK[32]` | `MetaKey[32]` |
| `"Arsenic V1 Meta Nonce"` | `DEK[32]` | `MetaNonce[12]` |
| `"Arsenic V1 Merkle Leaf v1"` | `encrypted_block` | `leaf_i[32]` |
| `"Arsenic V1 Merkle Node v1"` | `left[32] ‖ right[32]` | `node[32]` |
| `"Arsenic V1 KEK Nonce XChaCha20"` | `kek_nonce[12]` | extended nonce [24] |
| `"Arsenic V1 KEK Nonce DeoxysII256"` | `kek_nonce[12]` | extended nonce [15] |
| `"Arsenic Hybrid KEM"` | see §5 | ML-KEM-768 `wrapping_key[32]` |
| `"Arsenic Hybrid KEM 1024"` | see §5 | ML-KEM-1024 `wrapping_key[32]` |
| `"Arsenic ML-KEM d"` | `x25519_sk[32]` | `d[32]` (legacy ML-KEM seed) |
| `"Arsenic ML-KEM z"` | `x25519_sk[32]` | `z[32]` (legacy ML-KEM seed) |

---

## 4. AEAD Ciphers

All three produce a **16-byte authentication tag**. `hdr_cipher_id` and `pld_cipher_id` are independent.

### 4a. Deoxys-II-256 *(default header cipher)*

| Property | Value |
|---|---|
| Type | Tweakable block cipher AEAD (beyond-birthday-bound security) |
| Key size | 256 bits |
| Native nonce | 15 bytes |
| Tag | 128 bits |
| Hardware acceleration | AES-NI |

### 4b. XChaCha20-Poly1305 *(default payload cipher)*

| Property | Value |
|---|---|
| Type | Stream cipher + MAC (ARX) |
| Key size | 256 bits |
| Native nonce | 192 bits (24 bytes) |
| Tag | 128 bits |
| Hardware acceleration | None (fast in software) |

### 4c. AES-256-GCM-SIV

| Property | Value |
|---|---|
| Type | Synthetic IV AEAD |
| Key size | 256 bits |
| Native nonce | 12 bytes |
| Tag | 128 bits |
| Nonce-misuse resistant | Yes |
| Hardware acceleration | AES-NI + CLMUL |

---

## 5. Post-quantum Hybrid KEM

Asymmetric encryption uses a **hybrid KEM** combining X25519 (classical) and ML-KEM (post-quantum).

| Level | ML-KEM variant | EK size | CT size | Quantum security |
|---|---|---|---|---|
| **L768** *(default)* | ML-KEM-768 (NIST FIPS 203, level 3) | 1184 B | 1088 B | ~180 bits |
| **L1024** | ML-KEM-1024 (NIST FIPS 203, level 5) | 1568 B | 1568 B | ~256 bits |

### Hybrid binding

```
wrapping_key = BLAKE3_derive_key("Arsenic Hybrid KEM",
    eph_x25519_pk[32] ‖ mlkem_ct[1088] ‖ ss_x25519[32] ‖ ss_mlkem[32])
```

Security holds if **either** component is unbroken: X25519 breaks under Shor,
ML-KEM breaks only if lattice assumptions fail.

### Independent key seeds

X25519 and ML-KEM seeds are generated independently from the OS CSPRNG.
A single `.key` file covers both KEM levels from the same 64-byte ML-KEM seed.

---

## 6. Merkle Tree

**Role:** verify the integrity of the entire encrypted file before any plaintext is written.

```
leaf_i     = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", encrypted_block_i)
node(l, r) = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", l[32] ‖ r[32])
```

Distinct context strings for leaves and nodes prevent second-preimage confusion attacks.
The root is stored in ProtectedMetadata (encrypted under the DEK) and verified in
Pass 1 before any plaintext is written in Pass 2.

For **compressed files**, the Merkle tree covers compressed+encrypted blocks.
Decompression happens after full Merkle verification.

---

## 7. Bech32

**Role:** human-readable key encoding without a checksum (keys are cryptographically verified on use).

| Type | Prefix | Length |
|---|---|---|
| X25519 public key | `arsenic1` | 60 chars |
| Private key | `ARSENIC-SECRET-KEY-1` | 72 chars (uppercase = danger) |
| ML-KEM-768 encapsulation key | `arsenic1m` | ~1 955 chars |
| ML-KEM seed | `ARSENIC-MLKEM-SEED-1` | ~123 chars |

---

## 8. zstd Compression

**Role:** optional payload compression to reduce ciphertext size.

**Algorithm:** zstd (Zstandard) — fast lossless compressor, RFC 8878.

**Position in pipeline:** plaintext is compressed **before** encryption.
The Merkle tree and AEAD tags cover compressed+encrypted data.

**When active:** TLV tag `0x07` (`COMPRESS_ALGO_ID = 0x01`) is present in ProtectedMetadata.
`OriginalSize` (TLV `0x03`) always stores the **uncompressed** plaintext size.

**Compression level:** 1 (fast) to 22 (maximum), configurable at encryption time.
The level is not stored — only the algorithm ID is needed for decryption (zstd auto-detects).

**Security warning:** compression leaks plaintext entropy via ciphertext size.
An observer can infer content characteristics (language, structure, redundancy)
from the compression ratio — analogous to the CRIME/BREACH attacks on TLS compression.
**Disable for size-sensitive data.**

---

## 9. Zeroize

**Role:** securely erase sensitive values from memory on drop.

Values covered by `Secret<T>` (zeroized on drop):
- Password
- DEK — Data Encryption Key (+ explicit `zeroize()` after use)
- KEK — Key Encryption Key
- Intermediate `dek_vec` during envelope decryption
- Extra passphrase slot KEKs

The `ml-kem` crate uses the `zeroize` feature for internal key material.

---

## 10. Overview

```
Password ──► Argon2id ──► KEK[32] ──► AEAD ──► Primary WrappedDEK[48]
                                             ──► Extra WrappedDEK[48] × K
                      ┌──────────────────────────────────┘
                      ▼
               DEK[32] (random per file)
                      │
   ┌──────────────────┼──────────────────────────────────┐
   │                  │                                  │
   ▼                  ▼                                  ▼
[optional]     BLAKE3 → block_key/nonce         BLAKE3 → MetaKey/MetaNonce
 zstd compress    │                                      │
   │              ▼                                      ▼
   │       AEAD(block_key_i, block_nonce_i, aad_i,   AEAD(MetaKey, MetaNonce,
   │           compressed_plaintext_i)                "...", TLV[50+])
   │              │                                      │
   ▼              ▼                                      ▼
Original     Encrypted blocks                    ProtectedMetadata
plaintext      (Merkle tree covers these)         (in header)

For each recipient:
  X25519_ECDH + ML-KEM-768/1024.Encaps
  → BLAKE3 "Arsenic Hybrid KEM"
  → wrapping_key → AEAD → Hybrid WrappedDEK (in keyslot)
```

### Post-quantum Resistance Summary

| Component | Algorithm | PQ-safe? |
|---|---|---|
| Payload encryption | XChaCha20 / Deoxys-II / AES-GCM-SIV | ✓ (256-bit symmetric) |
| Password KDF | Argon2id | ✓ |
| Header MAC | BLAKE3_keyed_hash | ✓ |
| Internal derivation | BLAKE3 | ✓ |
| X25519 component | X25519 | ✗ (Shor) |
| ML-KEM-768 component | ML-KEM-768 FIPS 203 | ✓ (~180-bit quantum) |
| ML-KEM-1024 component | ML-KEM-1024 FIPS 203 | ✓ (~256-bit quantum) |
| **Hybrid keyslot** | **X25519 + ML-KEM** | **✓ (secure if either holds)** |
| Compression | zstd | N/A (not cryptographic) |
