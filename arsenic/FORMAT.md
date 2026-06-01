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
│  HeaderMAC                32 bytes          │  HMAC-SHA256
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
KEK       = Argon2id(password, salt, t_cost, m_cost, p_cost)  → 32 bytes
HeaderMAC = HMAC-SHA256( KEK[32], pre_mac[77] )               → 32 bytes
```

The HeaderMAC is keyed with the full KEK, so every password attempt
costs the full Argon2id derivation. A wrong password produces a wrong KEK
whose HMAC does not match — the mismatch is detected before any AEAD
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
│  hybrid_count  (u32 LE)         4 bytes  (offset 0x9D)       │
├──────────────────────────────────────────────────────────────┤
│  Hybrid keyslot #0           1 180 bytes  ┐                  │
│  Hybrid keyslot #1           1 180 bytes  │  × N             │
│  …                                        ┘                  │
├──────────────────────────────────────────────────────────────┤
│  ProtectedMetadata             variable   (TLV_len + 16)     │
└──────────────────────────────────────────────────────────────┘
```

### 5.1 Symmetric WrappedDEK (48 bytes)

```
WrappedDEK = AEAD_hdr( KEK[32], nonce_env(kek_nonce), [], DEK[32] )
           = ciphertext[32] || tag[16]
```

### 5.2 Counter (4 bytes)

`hybrid_count` (u32 LE): number N of hybrid keyslots. 0 if no recipients.

### 5.3 Hybrid Keyslot — 1 180 bytes each

Each keyslot allows a recipient to decrypt the file **without knowing the password**. It uses a post-quantum hybrid KEM.

```
Offset  Size  Field                Description
──────────────────────────────────────────────────────────────────────────────
  0      32   ephemeral_x25519     Ephemeral X25519 public key
 32    1088   mlkem_ciphertext     ML-KEM-768 ciphertext
1120     12   kek_nonce            AEAD nonce
1132     48   wrapped_dek          AEAD(wrapping_key, kek_nonce, [], DEK)
──────────────────────────────────────────────────────────────────────────────
                                   Total: 1 180 bytes
```

**Hybrid wrapping key computation:**

```
Encryption:
  ephemeral_x25519_sk  ← 32 random bytes
  ephemeral_x25519_pk  ← X25519PublicKey(ephemeral_x25519_sk)
  ss_x25519            ← X25519_ECDH(ephemeral_x25519_sk, recipient.x25519)

  m[32]                ← 32 random bytes
  (mlkem_ct, ss_mlkem) ← ML-KEM-768.Encaps(recipient.mlkem, m)

  wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM",
                   ephemeral_x25519_pk[32] || mlkem_ct[1088]
                   || ss_x25519[32] || ss_mlkem[32])

  wrapped_dek  ← AEAD_hdr(wrapping_key, kek_nonce, [], DEK)

Decryption:
  ss_x25519  ← X25519_ECDH(recipient_x25519_sk, ephemeral_x25519_pk)
  ss_mlkem   ← ML-KEM-768.Decaps(recipient_x25519_sk_seed, mlkem_ct)
  wrapping_key ← same BLAKE3
  DEK        ← AEAD_hdr_decrypt(wrapping_key, kek_nonce, wrapped_dek)
```

**ML-KEM key derived from X25519 key:**

The ML-KEM-768 secret key is deterministically derived from the X25519 private key:
```
seed[64] = BLAKE3_derive_key("Arsenic ML-KEM d", x25519_sk)[32]
        || BLAKE3_derive_key("Arsenic ML-KEM z", x25519_sk)[32]

(dk_mlkem, ek_mlkem) ← ML-KEM-768.KeyGen_internal(seed)
```

A single 32-byte `.key` file is sufficient; both keys are recomputed on use.

### 5.4 ProtectedMetadata (variable size)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce), [], meta_tlv )
                  = ciphertext[len(meta_tlv)] || tag[16]
```

**Mandatory TLV fields (60 bytes):**

| Tag    | Length | Value                                  |
|--------|--------|----------------------------------------|
| `0x02` | 32     | MerkleRoot (BLAKE3 root)               |
| `0x03` | 8      | OriginalSize (u64 LE)                  |
| `0x04` | 8      | CompressedSize (u64 LE, = OriginalSize)|
| `0x05` | 1      | BlockSizeId                            |
| `0x06` | 1      | MerkleAlgoId = `0x01`                  |

**Optional TLV fields:**

| Tag    | Max  | Value                           |
|--------|------|---------------------------------|
| `0x10` | 255  | Filename (UTF-8)                |
| `0x11` | 255  | Comment (UTF-8)                 |
| `0x12` | 8    | TimestampSecs (u64 LE)          |

---

## 6. Header Size

```
header_total_size = PUB_HEADER_LEN(109)
                  + WRAPPED_DEK_LEN(48)
                  + ASYM_COUNT_LEN(4)
                  + N × HYBRID_KEYSLOT_LEN(1180)
                  + len(meta_tlv) + GCM_TAG(16)
```

| Configuration             | Header size                 |
|---------------------------|-----------------------------|
| Minimum (0 keyslots)      | **237 bytes**               |
| 1 hybrid recipient        | 1 417 bytes                 |
| N hybrid recipients       | 237 + N × 1 180 bytes       |
| Maximum (256 keyslots)    | ~303 KiB                    |

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
| Deoxys-II-256      | 15 bytes        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce‖0×20)[0..15]` |
| XChaCha20-Poly1305 | 24 bytes        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20",   kek_nonce‖0×20)[0..24]` |

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
  ├── Argon2id(t=1, m=8192Ki, p=1, salt)    → PreKey[32]
  │         └── HMAC-SHA256(PreKey, pre_mac[77])   → HeaderMAC[32]
  │
  └── Argon2id(t_cost, m_cost, p_cost, salt) → KEK[32]
            └── AEAD_hdr(KEK, nonce_env(kek_nonce), [], DEK) → WrappedDEK[48]

random → DEK[32]
  ├── BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)           → MetaKey[32]
  ├── BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]    → MetaNonce[12]
  ├── For block i:
  │     BLAKE3_keyed_hash(DEK, i.to_le_bytes())                   → block_key_i[32]
  │     BLAKE3_derive_key("Arsenic V1 Block Nonce",
  │                        file_base_nonce||i.to_le_bytes())[0..24] → block_nonce_i[24]
  └── For hybrid keyslot j:
        random → ephemeral_x25519_sk[32] → ephemeral_x25519_pk[32]
        X25519_ECDH(ephemeral_x25519_sk, recipient.x25519)         → ss_x25519[32]
        random → m[32]
        ML-KEM-768.Encaps(recipient.mlkem, m)                      → (mlkem_ct[1088], ss_mlkem[32])
        BLAKE3_derive_key("Arsenic Hybrid KEM",
          eph_x25519_pk||mlkem_ct||ss_x25519||ss_mlkem)            → wrapping_key[32]
        AEAD_hdr(wrapping_key, kek_nonce_j, [], DEK)               → wrapped_dek_j[48]
```

---

## 11. Complete Diagram — Minimal File (0 keyslots)

```
Offset     Size  Content
─────────────────────────────────────────────────────────────────────────────
0x000000     4   magic            : 41 52 53 4E
0x000004     2   version          : 00 01
0x000006     1   kdf_id           : 01
0x000007     1   hdr_cipher_id    : e.g. 02
0x000008     1   pld_cipher_id    : e.g. 03
0x000009     4   header_total_size: ED 00 00 00  (237, u32 LE)
0x00000D    16   salt             : [16 random bytes]
0x00001D     4   t_cost           : 04 00 00 00
0x000021     4   m_cost           : 00 00 04 00  (262 144 KiB)
0x000025     4   p_cost           : 04 00 00 00
0x000029    24   file_base_nonce  : [24 random bytes]
0x000041    12   kek_nonce        : [12 random bytes]
──────── end pre-MAC section: 77 bytes ──────────────────────────────────────
0x00004D    32   HeaderMAC        : HMAC-SHA256(PreKey, pre_mac[77])
──────── end public header: 109 bytes ───────────────────────────────────────
0x00006D    48   WrappedDEK       : AEAD_hdr(KEK, ...)
0x00009D     4   hybrid_count     : 00 00 00 00
0x0000A1    76   ProtectedMetadata: AEAD_hdr(MetaKey, ..., TLV[60]) + tag[16]
──────── end header: 237 bytes ──────────────────────────────────────────────
0x0000ED     ∞   Payload (consecutive blocks)
─────────────────────────────────────────────────────────────────────────────
```

---

## 12. Password Change (rekey)

Only the `WrappedDEK` (48 bytes) is re-encrypted. The payload, ProtectedMetadata and hybrid keyslots do not change. Atomicity guaranteed by a fsynced `.bak` before any in-place write.

---

## 13. User Identities

| Component               | Size        | Storage       |
|-------------------------|-------------|---------------|
| X25519 private key      | 32 bytes    | `.key` (seed) |
| X25519 public key       | 32 bytes    | derived       |
| ML-KEM-768 seed         | 64 bytes    | derived from X25519 |
| ML-KEM encapsulation key (EK) | 1 184 bytes | derived    |
| ML-KEM decapsulation key (DK) | 2 400 bytes | RAM only   |

A single `.key` file (32 bytes encoded as `ARSENIC-SECRET-KEY-1{bech32}`) is sufficient for the full hybrid keypair.

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
| Header integrity                  | HMAC-SHA256 over 77 bytes (KDF params + cipher IDs)             |
| Fast oracle resistance            | PreKey via mini-Argon2id (~15 000 H/s on GPU)                   |
| DoS resistance (KDF params)       | Forged params rejected by MAC before any Argon2id               |
| Quantum resistance — payload      | Symmetric 256 bits: Grover requires 2¹²⁸ — already post-quantum |
| Quantum resistance — keyslots     | ML-KEM-768 (NIST level 3) resists Shor                          |
| Defence in depth                  | Hybrid X25519+ML-KEM: a flaw in one does not compromise the other |
| Harvest-now-decrypt-later         | ML-KEM protects files encrypted today                            |
| Recipient anonymity               | Keyslots do not reveal the recipient's public key               |
| Merkle domain separation          | BLAKE3_derive_key with distinct contexts                        |
| Memory erasure                    | `Secret<T>` calls `zeroize` on drop                             |
