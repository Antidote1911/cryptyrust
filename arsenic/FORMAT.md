> [Version française](FORMAT_fr.md)

# Arsenic V1 File Format — Complete Specification

> **Format version**: `[0x00, 0x01]`  
> **Magic**: `41 52 53 4E` ("ARSN")  
> **Usual extension**: `.arsn`  
> All multi-byte values are **little-endian** unless stated otherwise.

---

## 1. Overview

An Arsenic V1 file consists of two consecutive parts:

```
┌───────────────────────────────────────────────┐  ← offset 0
│  Header  (variable size)                      │  length = header_total_size
├───────────────────────────────────────────────┤  ← offset header_total_size
│  Encrypted payload (consecutive AEAD blocks)  │  until end of file
└───────────────────────────────────────────────┘
```

The `header_total_size` field (u32 LE at offset 0x09) encodes the exact header length. The payload begins immediately after.

---

## 2. Header Structure

```
┌─────────────────────────────────────────────┐  offset 0x00
│  Pre-MAC section          77 bytes          │  covered by HeaderMAC
├─────────────────────────────────────────────┤  offset 0x4D
│  HeaderMAC                32 bytes          │  BLAKE3_keyed_hash(KEK, pre-MAC)
├─────────────────────────────────────────────┤  offset 0x6D  (PUB_HEADER_LEN = 109)
│  Envelope region          variable          │  wrapped keys + encrypted metadata
└─────────────────────────────────────────────┘  offset header_total_size
```

---

## 3. Pre-MAC Section (bytes 0x00 – 0x4C, 77 bytes)

These 77 bytes are fully covered by the HeaderMAC.

```
Offset  Size  Field                Description
──────────────────────────────────────────────────────────────────────────────
0x00      4   magic                Fixed bytes: 41 52 53 4E  ("ARSN")
0x04      2   version              Fixed bytes: 00 01
0x06      1   kdf_id               01 = Argon2id
0x07      1   hdr_cipher_id        Envelope cipher (see §9)
0x08      1   pld_cipher_id        Payload cipher (see §9)
0x09      4   header_total_size    u32 LE — total header size
0x0D     16   salt                 Argon2id salt (16 random bytes)
0x1D      4   t_cost               u32 LE — Argon2id iterations
0x21      4   m_cost               u32 LE — memory in KiB
0x25      4   p_cost               u32 LE — Argon2id parallelism
0x29     24   file_base_nonce      Block nonce base (random)
0x41     12   kek_nonce            AEAD nonce for the symmetric keyslot
──────────────────────────────────────────────────────────────────────────────
                                   Total: 77 bytes  (PRE_MAC_LEN = 0x4D)
```

---

## 4. HeaderMAC (bytes 0x4D – 0x6C, 32 bytes)

```
KEK       = Argon2id(password, salt, t_cost, m_cost, p_cost)   → 32 bytes
HeaderMAC = BLAKE3_keyed_hash( key=KEK[32], data=pre_mac[77] ) → 32 bytes
```

BLAKE3 is used throughout the format for all internal derivations; the
HeaderMAC uses it for consistency (replaces the former HMAC-SHA256).
BLAKE3's keyed-hash comparison is constant-time.

The HeaderMAC is keyed with the full KEK, so every password attempt
costs the full Argon2id derivation. A wrong password produces a wrong KEK
whose MAC does not match — the mismatch is detected before any AEAD
decryption is attempted.

**DoS protection:** before invoking Argon2id the implementation validates
that the declared KDF parameters are within safe bounds
(`t_cost ≤ 64`, `m_cost ≤ 4 GiB`, `p_cost ≤ 16`). A tampered file
with absurd parameters is rejected immediately at zero cost.

**End of public header: 109 bytes** (`PUB_HEADER_LEN = 0x6D`).

---

## 5. Envelope Region (offset 0x6D, variable size)

```
┌──────────────────────────────────────────────────────────────┐
│  Symmetric WrappedDEK          48 bytes  (offset 0x6D)       │
├──────────────────────────────────────────────────────────────┤
│  hybrid_768_count  (u32 LE)     4 bytes  (offset 0x9D)       │
├──────────────────────────────────────────────────────────────┤
│  ML-KEM-768 keyslot #0       1 180 bytes  ┐                  │
│  ML-KEM-768 keyslot #1       1 180 bytes  │  × N             │
│  …                                        ┘                  │
├──────────────────────────────────────────────────────────────┤
│  hybrid_1024_count (u32 LE)     4 bytes                      │
├──────────────────────────────────────────────────────────────┤
│  ML-KEM-1024 keyslot #0      1 660 bytes  ┐                  │
│  ML-KEM-1024 keyslot #1      1 660 bytes  │  × M             │
│  …                                        ┘                  │
├──────────────────────────────────────────────────────────────┤
│  ProtectedMetadata             variable   (TLV_len + 16)     │
├──────────────────────────────────────────────────────────────┤
│  sig_present                    1 byte    0x00 or 0x01       │
│  [ML-DSA-65 verifying key]   1 952 bytes  ┐ present only     │
│  [ML-DSA-65 signature]       3 309 bytes  ┘ if sig=0x01      │
└──────────────────────────────────────────────────────────────┘
```

The sender selects **one** KEM level per file: either all keyslots are ML-KEM-768
(N > 0, M = 0) or all are ML-KEM-1024 (N = 0, M > 0). Mixed levels within the
same file are not used in practice, but parsers must handle both counts.

### 5.1 Symmetric WrappedDEK (48 bytes)

```
WrappedDEK = AEAD_hdr( KEK[32], nonce_env(kek_nonce),
                        "arsenic-v1-wrapped-dek", DEK[32] )
           = ciphertext[32] || tag[16]
```

### 5.2 Counters (4 bytes each)

`hybrid_768_count` (u32 LE): number N of ML-KEM-768 keyslots.  
`hybrid_1024_count` (u32 LE): number M of ML-KEM-1024 keyslots.  
Both are 0 if no asymmetric recipients.

### 5.3 ML-KEM-768 Hybrid Keyslot — 1 180 bytes each

```
Offset  Size  Field                Description
──────────────────────────────────────────────────────────────────────────────
  0      32   ephemeral_x25519     Ephemeral X25519 public key
 32    1088   mlkem_ciphertext     ML-KEM-768 ciphertext
1120     12   kek_nonce            AEAD nonce
1132     48   wrapped_dek          AEAD(wrapping_key, kek_nonce, aad, DEK)
──────────────────────────────────────────────────────────────────────────────
                                   Total: 1 180 bytes
```

**Hybrid wrapping key computation (ML-KEM-768):**

```
Encryption:
  ephemeral_x25519_sk  ← OS random [32]
  ephemeral_x25519_pk  ← X25519PublicKey(ephemeral_x25519_sk)
  ss_x25519            ← X25519_ECDH(ephemeral_x25519_sk, recipient.x25519_pk)

  m[32]                ← OS random [32]
  (mlkem_ct, ss_mlkem) ← ML-KEM-768.Encaps(recipient.mlkem_768_ek, m)

  wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM",
                   ephemeral_x25519_pk[32] || mlkem_ct[1088]
                   || ss_x25519[32] || ss_mlkem[32])

  wrapped_dek  ← AEAD_hdr(wrapping_key, kek_nonce,
                            "arsenic-v1-hybrid-wrapped-dek", DEK)

Decryption:
  ss_x25519    ← X25519_ECDH(recipient_x25519_sk, ephemeral_x25519_pk)
  ss_mlkem     ← ML-KEM-768.Decaps(recipient_mlkem_768_seed, mlkem_ct)
  wrapping_key ← same BLAKE3
  DEK          ← AEAD_hdr_decrypt(wrapping_key, kek_nonce, wrapped_dek)
```

**Independent key seeds (since v1.5.0):**

The recipient's X25519 and ML-KEM-768 seeds are **independent**: the `.key`
file stores a 32-byte X25519 seed and a separate 64-byte ML-KEM seed
(`d[32] || z[32]`) generated independently from the OS CSPRNG. Legacy key files
(without `# mlkem-seed:`) derive the ML-KEM seed via BLAKE3 for compatibility.

### 5.4 ML-KEM-1024 Hybrid Keyslot — 1 660 bytes each

Same structure as §5.3 but using ML-KEM-1024 (NIST Level 5, ~256-bit quantum
security). The BLAKE3 binding uses a distinct context string.

```
Offset  Size  Field                Description
──────────────────────────────────────────────────────────────────────────────
  0      32   ephemeral_x25519     Ephemeral X25519 public key
 32    1568   mlkem_ciphertext     ML-KEM-1024 ciphertext
1600     12   kek_nonce            AEAD nonce
1612     48   wrapped_dek          AEAD(wrapping_key, kek_nonce, aad, DEK)
──────────────────────────────────────────────────────────────────────────────
                                   Total: 1 660 bytes
```

The ML-KEM-1024 wrapping key uses context `"Arsenic Hybrid KEM 1024"`:
```
wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM 1024",
                 ephemeral_x25519_pk[32] || mlkem_ct[1568]
                 || ss_x25519[32] || ss_mlkem[32])
```

### 5.5 ProtectedMetadata (variable size)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce),
                               "arsenic-v1-protected-meta", meta_tlv )
                  = ciphertext[len(meta_tlv)] || tag[16]
```

### 5.6 Signature Region (variable size)

The last bytes of the envelope encode an optional ML-DSA-65 signature
(NIST FIPS 204, ~192-bit quantum security).

```
sig_present[1]       0x00 = no signature
                     0x01 = ML-DSA-65 signature follows

[if sig_present == 0x01]:
  verifying_key[1952]  ML-DSA-65 verifying (public) key
  signature[3309]      ML-DSA-65 signature

Signed message = pre_mac[77]  (covers all KDF params, cipher IDs, nonces)
```

The signature is verified automatically during decryption; a mismatch is a
hard error. Signers use a separate `.sigkey` file (32-byte ML-DSA seed).

### 5.4 ProtectedMetadata (variable size)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce), "arsenic-v1-protected-meta", meta_tlv )
                  = ciphertext[len(meta_tlv)] || tag[16]
```

**Mandatory TLV fields (50 bytes):**

| Tag    | Length | Value                     |
|--------|--------|---------------------------|
| `0x02` | 32     | MerkleRoot (BLAKE3 root)  |
| `0x03` | 8      | OriginalSize (u64 LE)     |
| `0x05` | 1      | BlockSizeId               |
| `0x06` | 1      | MerkleAlgoId = `0x01`     |

Tag `0x04` (CompressedSize) was removed — it always equalled OriginalSize.

**Optional TLV fields:**

| Tag    | Max  | Value                  |
|--------|------|------------------------|
| `0x10` | 255  | Filename (UTF-8)       |
| `0x11` | 255  | Comment (UTF-8)        |
| `0x12` | 8    | TimestampSecs (u64 LE) |

---

## 6. Header Size

```
header_total_size = PUB_HEADER_LEN(109)
                  + WRAPPED_DEK_LEN(48)
                  + ASYM_768_COUNT_LEN(4)  + N × KEYSLOT_768_LEN(1180)
                  + ASYM_1024_COUNT_LEN(4) + M × KEYSLOT_1024_LEN(1660)
                  + len(meta_tlv) + GCM_TAG(16)
                  + SIG_PRESENT_LEN(1)
                  [+ MLDSA_VK_LEN(1952) + MLDSA_SIG_LEN(3309)  if signed]
```

| Configuration                          | Header size        |
|----------------------------------------|--------------------|
| Minimum (0 keyslots, no signature)     | **232 bytes**      |
| 1 ML-KEM-768 recipient, no signature   | 1 412 bytes        |
| N ML-KEM-768 recipients, no signature  | 232 + N × 1 180    |
| 1 ML-KEM-1024 recipient, no signature  | 1 892 bytes        |
| M ML-KEM-1024 recipients, no signature | 232 + M × 1 660    |
| Any recipients + ML-DSA-65 signature   | + 5 261 bytes      |
| Maximum (256 keyslots)                 | ~303 KiB           |

Limits: `MAX_ASYM_KEYSLOTS = 256`, `MAX_HEADER_TOTAL_SIZE = 64 MiB`.

---

## 7. Encrypted Payload

The payload starts at offset `header_total_size` and extends to the end of the file. It consists of **independent AEAD blocks**.

### 7.1 Block Size

| BlockSizeId | Plaintext size         | Condition        |
|-------------|------------------------|------------------|
| `0x01`      | 4 194 304 bytes (4 MiB) | Files < 4 GiB   |
| `0x02`      | 33 554 432 bytes (32 MiB)| Files ≥ 4 GiB  |

### 7.2 Block Key and Nonce Derivation

For block `i` (u64 LE, starting at 0):

```
block_key_i[32]   ← BLAKE3_keyed_hash(key=DEK, data=i.to_le_bytes()[8])
material[32]      ← file_base_nonce[24] || i.to_le_bytes()[8]
block_nonce_i[24] ← BLAKE3_derive_key("Arsenic V1 Block Nonce", material)[0..24]
aad_i[8]          ← i.to_le_bytes()
```

### 7.3 On-disk Layout

Blocks concatenated without separator:

```
block_0[ N₀ + 16 ] || block_1[ N₁ + 16 ] || … || block_k[ Nₖ + 16 ]
```

where `block_i = AEAD_pld(block_key_i, block_nonce_i_truncated, aad_i, plaintext_i)`.

---

## 8. Merkle Tree

Computed over **encrypted blocks**, before any plaintext is written:

```
leaf_i[32]           ← BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", encrypted_block_i)
node(left, right)    ← BLAKE3_derive_key("Arsenic V1 Merkle Node v1", left[32] || right[32])
```

Construction: successive pairs bottom-up; an odd node is promoted as-is (no duplication). Root stored in ProtectedMetadata (tag `0x02`).

| Blocks | Root          |
|--------|---------------|
| 0      | `[0u8; 32]`   |
| 1      | `leaf_0`      |
| N > 1  | Recursive tree|

---

## 9. AEAD Ciphers

All produce a **16-byte** tag. `hdr_cipher_id` and `pld_cipher_id` are independent.

### 9.1 Identifiers

| cipher_id | Algorithm                | Native nonce |
|-----------|--------------------------|--------------|
| `0x02`    | Deoxys-II-256            | 15 bytes     |
| `0x03`    | XChaCha20-Poly1305       | 24 bytes     |
| `0x04`    | AES-256-GCM-SIV          | 12 bytes     |

### 9.2 Envelope Nonce Expansion (12-byte kek_nonce)

| Algorithm          | Effective nonce | Procedure |
|--------------------|-----------------|-----------|
| AES-256-GCM-SIV    | 12 bytes        | `kek_nonce[0..12]` directly |
| Deoxys-II-256      | 15 bytes        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce[12])[0..15]` |
| XChaCha20-Poly1305 | 24 bytes        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20",   kek_nonce[12])[0..24]` |

### 9.3 Block Nonce Truncation (24 derived bytes)

| Algorithm          | Bytes used                 |
|--------------------|----------------------------|
| AES-256-GCM-SIV    | `block_nonce_i[0..12]`     |
| Deoxys-II-256      | `block_nonce_i[0..15]`     |
| XChaCha20-Poly1305 | `block_nonce_i[0..24]`     |

---

## 10. Derivation Chain — Summary

```
password
  │
  └── Argon2id(t_cost, m_cost, p_cost, salt) → KEK[32]
        ├── BLAKE3_keyed_hash(KEK, pre_mac[77])            → HeaderMAC[32]
        └── AEAD_hdr(KEK, nonce_env(kek_nonce),
                     "arsenic-v1-wrapped-dek", DEK)        → WrappedDEK[48]

OS random → DEK[32]
  ├── BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)    → MetaKey[32]
  ├── BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12] → MetaNonce[12]
  ├── For block i:
  │     BLAKE3_keyed_hash(DEK, i.to_le_bytes())            → block_key_i[32]
  │     BLAKE3_derive_key("Arsenic V1 Block Nonce",
  │       file_base_nonce||i.to_le_bytes())[0..24]         → block_nonce_i[24]
  ├── For ML-KEM-768 keyslot j:
  │     OS random → eph_x25519_sk[32] → eph_x25519_pk[32]
  │     X25519_ECDH(eph_x25519_sk, recipient.x25519_pk)   → ss_x25519[32]
  │     OS random → m[32]
  │     ML-KEM-768.Encaps(recipient.mlkem_768_ek, m)       → (mlkem_ct[1088], ss_mlkem[32])
  │     BLAKE3_derive_key("Arsenic Hybrid KEM",
  │       eph_x25519_pk||mlkem_ct||ss_x25519||ss_mlkem)   → wrapping_key_j[32]
  │     AEAD_hdr(wrapping_key_j, kek_nonce_j,
  │              "arsenic-v1-hybrid-wrapped-dek", DEK)     → wrapped_dek_j[48]
  └── For ML-KEM-1024 keyslot k:
        (same as above but ML-KEM-1024, mlkem_ct[1568],
         context = "Arsenic Hybrid KEM 1024")

[optional — if signing_key provided]:
  ML-DSA-65.Sign(signing_key_seed[32], pre_mac[77])        → signature[3309]
  + verifying_key[1952] appended to header
```

---

## 11. Complete Diagram — Minimal File (0 keyslots, no signature)

```
Offset     Size  Content
─────────────────────────────────────────────────────────────────────────────
0x000000     4   magic              : 41 52 53 4E
0x000004     2   version            : 00 01
0x000006     1   kdf_id             : 01
0x000007     1   hdr_cipher_id      : e.g. 02
0x000008     1   pld_cipher_id      : e.g. 03
0x000009     4   header_total_size  : E8 00 00 00  (232, u32 LE)
0x00000D    16   salt               : [16 random bytes]
0x00001D     4   t_cost             : 04 00 00 00
0x000021     4   m_cost             : 00 00 04 00  (262 144 KiB)
0x000025     4   p_cost             : 04 00 00 00
0x000029    24   file_base_nonce    : [24 random bytes]
0x000041    12   kek_nonce          : [12 random bytes]
──────── end pre-MAC section: 77 bytes ──────────────────────────────────────
0x00004D    32   HeaderMAC          : BLAKE3_keyed_hash(KEK, pre_mac[77])
──────── end public header: 109 bytes ───────────────────────────────────────
0x00006D    48   WrappedDEK         : AEAD_hdr(KEK, "arsenic-v1-wrapped-dek", DEK)
0x00009D     4   hybrid_768_count   : 00 00 00 00
0x0000A1     4   hybrid_1024_count  : 00 00 00 00
0x0000A5    66   ProtectedMetadata  : AEAD_hdr(MetaKey, "arsenic-v1-protected-meta", TLV[50])
0x0000E7     1   sig_present        : 00  (no signature)
──────── end header: 232 bytes ──────────────────────────────────────────────
0x0000E8     ∞   Payload (consecutive blocks)
─────────────────────────────────────────────────────────────────────────────
```

---

## 12. Password Change (rekey)

The following fields change; everything else is preserved unchanged:

| Field | Change |
|---|---|
| `salt` | New 16-byte random value |
| `kek_nonce` | New 12-byte random value |
| `HeaderMAC` | Recomputed with new KEK = Argon2id(new\_password, new\_salt) |
| `WrappedDEK` | Re-encrypted under new KEK |
| Hybrid keyslots | **Unchanged** |
| `ProtectedMetadata` | **Unchanged** |
| Payload blocks | **Unchanged** |

Because the KEK depends on both the password and the salt, and both change,
the entire 109-byte public header is rewritten together with the WrappedDEK.
The payload is never touched regardless of file size — rekey is O(1).

**Atomicity:** the full current header is written to `<file>.bak` and
fsynced (including the parent directory entry on POSIX) before any in-place
write. On success the backup is deleted. On crash, the original header is
restored from the backup on next open.

---

## 13. User Identities

### Encryption keypair (`.key` file)

| Component                      | Size        | Storage                                |
|--------------------------------|-------------|----------------------------------------|
| X25519 private key             | 32 bytes    | `ARSENIC-SECRET-KEY-1{bech32}` line    |
| ML-KEM seed (`d\|\|z`)        | 64 bytes    | `# mlkem-seed: ARSENIC-MLKEM-SEED-1{bech32}` |
| X25519 public key              | 32 bytes    | `# public key: arsenic1{bech32}`       |
| ML-KEM-768 encapsulation key   | 1 184 bytes | `# mlkem-public-key: arsenic1m{bech32}` |
| ML-KEM-768 decapsulation key   | 2 400 bytes | Computed in RAM, never stored          |
| ML-KEM-1024 encapsulation key  | 1 568 bytes | Derived from the same 64-byte ML-KEM seed |
| ML-KEM-1024 decapsulation key  | 3 168 bytes | Computed in RAM, never stored          |

The X25519 seed and ML-KEM seed are **independent** — each is generated from the OS CSPRNG independently. A single `.key` file is sufficient for all KEM levels.

Legacy key files (without `# mlkem-seed:`) derive the ML-KEM seed via BLAKE3 for backward compatibility.

### Signing keypair (`.sigkey` file)

| Component                      | Size        | Storage                                      |
|--------------------------------|-------------|----------------------------------------------|
| ML-DSA-65 seed                 | 32 bytes    | `ARSENIC-SIGN-SEED-1{bech32}` line           |
| ML-DSA-65 verifying key        | 1 952 bytes | `# verifying-key: ARSENIC-SIGN-PUB-1{bech32}` |
| ML-DSA-65 signing key          | 4 032 bytes | Reconstructed from seed, never stored         |

---

## 14. Security Properties

| Property                          | Mechanism                                                       |
|-----------------------------------|-----------------------------------------------------------------|
| DEK confidentiality               | AEAD under KEK (Argon2id); random 32-byte DEK                   |
| Metadata confidentiality          | AEAD under MetaKey = f(DEK)                                     |
| Payload confidentiality           | AEAD under per-block keys derived from DEK + index              |
| Per-block integrity               | 16-byte AEAD tag per block                                      |
| Whole-file integrity              | BLAKE3 Merkle root verified before any plaintext write          |
| Block ordering                    | Index bound as AAD in each block AEAD                           |
| Header integrity                  | BLAKE3_keyed_hash(KEK, 77 public bytes)                         |
| DoS resistance (KDF params)       | Params validated against bounds before any Argon2id             |
| Quantum resistance — payload      | Symmetric 256 bits: Grover requires 2¹²⁸ — already post-quantum |
| Quantum resistance — keyslots L3  | ML-KEM-768 (NIST level 3, ~180-bit quantum) resists Shor         |
| Quantum resistance — keyslots L5  | ML-KEM-1024 (NIST level 5, ~256-bit quantum) resists Shor        |
| Defence in depth                  | Hybrid X25519+ML-KEM: a flaw in one does not compromise the other |
| Harvest-now-decrypt-later         | ML-KEM protects files encrypted today                            |
| Sender authentication             | Optional ML-DSA-65 signature over pre\_mac (NIST FIPS 204)       |
| Independent key entropy           | X25519 and ML-KEM seeds generated independently from OS CSPRNG   |
| Recipient anonymity               | Keyslots do not reveal the recipient's public key               |
| Merkle domain separation          | BLAKE3_derive_key with distinct contexts                        |
| Memory erasure                    | `Secret<T>` calls `zeroize` on drop                             |
