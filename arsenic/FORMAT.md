# Arsenic V1 File Format — Complete Specification

> **Format version**: `[0x00, 0x01]`
> **Magic**: `41 52 53 4E` ("ARSN")
> **Usual extension**: `.arsn` (binary) · `.arsn.armor` (ASCII-armored)
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

**ASCII Armor** is an optional transport encoding that wraps the binary file in base64 with PEM-style delimiters.  It does not change the underlying binary format.

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
0x0D     16   salt                 Argon2id salt (primary slot)
0x1D      4   t_cost               u32 LE — Argon2id iterations (shared by all slots)
0x21      4   m_cost               u32 LE — memory in KiB (shared by all slots)
0x25      4   p_cost               u32 LE — Argon2id parallelism (shared by all slots)
0x29     24   file_base_nonce      Block nonce base (random)
0x41     12   kek_nonce            AEAD nonce for the primary symmetric keyslot
──────────────────────────────────────────────────────────────────────────────
                                   Total: 77 bytes  (PRE_MAC_LEN = 0x4D)
```

---

## 4. HeaderMAC (bytes 0x4D – 0x6C, 32 bytes)

```
KEK       = Argon2id(password, salt, t_cost, m_cost, p_cost)   → 32 bytes
HeaderMAC = BLAKE3_keyed_hash( key=KEK[32], data=pre_mac[77] ) → 32 bytes
```

The HeaderMAC provides fast-fail for wrong passwords on the **primary slot only**.
Extra passphrase slots (§5.2) have no HeaderMAC — wrong passwords pay the full
Argon2id cost for each extra slot. KDF params are shared across all slots.

**DoS protection:** KDF parameters are validated against safe bounds
(`t_cost ≤ 64`, `m_cost ≤ 4 GiB`, `p_cost ≤ 16`) before any Argon2id invocation.

**End of public header: 109 bytes** (`PUB_HEADER_LEN = 0x6D`).

---

## 5. Envelope Region (offset 0x6D, variable size)

```
┌──────────────────────────────────────────────────────────────┐
│  Primary WrappedDEK            48 bytes  (offset 0x6D)       │
├──────────────────────────────────────────────────────────────┤
│  extra_passphrase_count (u32)   4 bytes                      │
├──────────────────────────────────────────────────────────────┤
│  Extra passphrase slot #0      76 bytes  ┐                   │
│  Extra passphrase slot #1      76 bytes  │  × K (max 15)     │
│  …                                       ┘                   │
├──────────────────────────────────────────────────────────────┤
│  hybrid_768_count  (u32 LE)     4 bytes                      │
├──────────────────────────────────────────────────────────────┤
│  ML-KEM-768 keyslot #0       1 180 bytes  ┐                  │
│  …                                         │  × N            │
├──────────────────────────────────────────────────────────────┤
│  hybrid_1024_count (u32 LE)     4 bytes                      │
├──────────────────────────────────────────────────────────────┤
│  ML-KEM-1024 keyslot #0      1 660 bytes  ┐                  │
│  …                                         │  × M            │
├──────────────────────────────────────────────────────────────┤
│  ProtectedMetadata             variable   (TLV_len + 16)     │
├──────────────────────────────────────────────────────────────┤
│  sender_present                 1 byte    0x00 or 0x01       │
│  [sender name, keys]        ≥1223 bytes   if sender=0x01     │
└──────────────────────────────────────────────────────────────┘
```

### 5.1 Primary Symmetric WrappedDEK (48 bytes)

```
WrappedDEK = AEAD_hdr( KEK[32], nonce_env(kek_nonce),
                        "arsenic-v1-wrapped-dek", DEK[32] )
           = ciphertext[32] || tag[16]
```

Authentication: covered by HeaderMAC — wrong password fails before AEAD.

### 5.2 Extra Passphrase Slots (76 bytes each, max 15)

Each extra slot allows an independent password to decrypt the same file.
KDF parameters (`t_cost`, `m_cost`, `p_cost`) are shared from the pre-MAC section.

```
Offset  Size  Field          Description
──────────────────────────────────────────────────────────────────────────────
  0      16   salt           Independent Argon2id salt for this slot
 16      12   kek_nonce      AEAD nonce
 28      48   wrapped_dek    AEAD(KEK_extra, kek_nonce, "arsenic-v1-extra-pass-wrapped-dek", DEK)
──────────────────────────────────────────────────────────────────────────────
               Total: 76 bytes (EXTRA_PASS_SLOT_LEN)
```

No HeaderMAC covers extra slots — authentication relies solely on the AEAD tag
of `wrapped_dek`.

**Decryption order:** primary slot is tried first (HeaderMAC fast-fail). If the
primary MAC fails for the provided password, all extra slots are tried in order,
each paying the full Argon2id cost.

### 5.3 Counters (4 bytes each)

`hybrid_768_count` (u32 LE): number N of ML-KEM-768 keyslots.
`hybrid_1024_count` (u32 LE): number M of ML-KEM-1024 keyslots.
Both are 0 if no asymmetric recipients.

### 5.4 ML-KEM-768 Hybrid Keyslot — 1 180 bytes each

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

**Hybrid wrapping key (ML-KEM-768):**
```
wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM",
                 eph_pk[32] || mlkem_ct[1088] || ss_x25519[32] || ss_mlkem[32])
```

### 5.5 ML-KEM-1024 Hybrid Keyslot — 1 660 bytes each

Same structure as §5.4 but with 1568-byte ML-KEM-1024 ciphertext.
Context string: `"Arsenic Hybrid KEM 1024"`.

### 5.6 ProtectedMetadata (variable size)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce),
                               "arsenic-v1-protected-meta", meta_tlv )
```

**Mandatory TLV fields (50 bytes):**

| Tag    | Length | Value                     |
|--------|--------|---------------------------|
| `0x02` | 32     | MerkleRoot (BLAKE3 root)  |
| `0x03` | 8      | OriginalSize (u64 LE) — always the **uncompressed** size |
| `0x05` | 1      | BlockSizeId               |
| `0x06` | 1      | MerkleAlgoId = `0x01`     |

**Optional TLV fields:**

| Tag    | Max  | Value                                    |
|--------|------|------------------------------------------|
| `0x07` | 1    | CompressAlgoId: `0x01` = zstd. Absent = no compression. |
| `0x10` | 255  | Filename (UTF-8)                         |
| `0x11` | 255  | Comment (UTF-8)                          |
| `0x12` | 8    | TimestampSecs (u64 LE)                   |

**Compression (`0x07` present):** the payload blocks contain compressed data.
The Merkle tree covers compressed+encrypted blocks. On decryption, all blocks are
decrypted, concatenated, then decompressed (zstd). `OriginalSize` is validated
against the decompressed length.

> **Security warning:** enabling compression leaks plaintext entropy via ciphertext
> size. Do not use for size-sensitive data.

### 5.7 Sender Identity Region (variable size)

Stored in plaintext, readable without decryption. Advisory only — unauthenticated.

```
sender_present[1]       0x00 = none / 0x01 = present

[if present, tail-parsed]:
  name_bytes[N] || name_len[2 LE] || x25519_pk[32] || mlkem_pk[1184] || 0x01
```

---

## 6. Header Size

```
header_total_size = PUB_HEADER_LEN(109)
                  + WRAPPED_DEK_LEN(48)
                  + EXTRA_PASS_COUNT_LEN(4) + K × EXTRA_PASS_SLOT_LEN(76)
                  + ASYM_768_COUNT_LEN(4)  + N × KEYSLOT_768_LEN(1180)
                  + ASYM_1024_COUNT_LEN(4) + M × KEYSLOT_1024_LEN(1660)
                  + len(meta_tlv) + GCM_TAG(16)
                  + SENDER_PRESENT_LEN(1)
                  [+ name_len(2) + len(name) + X25519_PK(32) + MLKEM_PK(1184)  if sender]
```

| Configuration                                          | Header size     |
|--------------------------------------------------------|-----------------|
| Minimum (0 keyslots, 0 extra slots, no sender)         | **236 bytes**   |
| + 1 extra passphrase slot                              | + 76 bytes      |
| + 1 ML-KEM-768 recipient                               | + 1 180 bytes   |
| + 1 ML-KEM-1024 recipient                              | + 1 660 bytes   |
| + Sender (name = "alice", 5 bytes)                     | + 1 223 bytes   |
| + zstd compression TLV                                 | + 3 bytes       |
| Maximum (15 extra slots + 256 keyslots)                | ~303 KiB        |

Limits: `MAX_EXTRA_PASSPHRASE_SLOTS = 15`, `MAX_ASYM_KEYSLOTS = 256`,
`MAX_HEADER_TOTAL_SIZE = 64 MiB`.

---

## 7. Encrypted Payload

The payload starts at offset `header_total_size`. It consists of **independent AEAD blocks**.
When compression is active, the blocks contain zstd-compressed data.

### 7.1 Block Size

| BlockSizeId | Plaintext size | Selected when |
|-------------|----------------|---------------|
| `0x01`      | 4 MiB          | file < 4 GiB  |
| `0x02`      | 32 MiB         | file ≥ 4 GiB  |

For compressed files, block size is selected from the **compressed** payload size.

### 7.2 Block Key and Nonce Derivation

```
block_key_i[32]   ← BLAKE3_keyed_hash(key=DEK, data=i.to_le_bytes())
material[32]      ← file_base_nonce[24] || i.to_le_bytes()
block_nonce_i[24] ← BLAKE3_derive_key("Arsenic V1 Block Nonce", material)[0..24]
aad_i[8]          ← i.to_le_bytes()
```

---

## 8. Merkle Tree

Computed over **encrypted blocks** (after optional compression):

```
leaf_i     ← BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", encrypted_block_i)
node(l, r) ← BLAKE3_derive_key("Arsenic V1 Merkle Node v1", l[32] || r[32])
```

Root stored in ProtectedMetadata (tag `0x02`). Verified before any plaintext write.

---

## 9. AEAD Ciphers

| cipher_id | Algorithm            | Native nonce |
|-----------|----------------------|--------------|
| `0x02`    | Deoxys-II-256        | 15 bytes     |
| `0x03`    | XChaCha20-Poly1305   | 24 bytes     |
| `0x04`    | AES-256-GCM-SIV      | 12 bytes     |

Envelope nonces are BLAKE3-expanded from the 12-byte `kek_nonce` field.

---

## 10. ASCII Armor

Armor is a **transport encoding** — it does not change the binary format.

```
-----BEGIN ARSENIC ENCRYPTED FILE-----
<base64 of the binary .arsn file, 64-char lines>
-----END ARSENIC ENCRYPTED FILE-----
```

The armored form is detected automatically on decrypt (file starts with `-----BEGIN ARSENIC`).
Armor reveals the exact ciphertext length (leaks plaintext size lower bound).

---

## 11. Complete Diagram — Minimal File (0 keyslots, 0 extra slots, no sender)

```
Offset     Size  Content
─────────────────────────────────────────────────────────────────────────────
0x000000     4   magic              : 41 52 53 4E
0x000004     2   version            : 00 01
0x000006     1   kdf_id             : 01
0x000007     1   hdr_cipher_id
0x000008     1   pld_cipher_id
0x000009     4   header_total_size  : EC 00 00 00  (236, u32 LE)
0x00000D    16   salt
0x00001D     4   t_cost
0x000021     4   m_cost
0x000025     4   p_cost
0x000029    24   file_base_nonce
0x000041    12   kek_nonce
──────── end pre-MAC: 77 bytes ──────────────────────────────────────────────
0x00004D    32   HeaderMAC
──────── end public header: 109 bytes ───────────────────────────────────────
0x00006D    48   Primary WrappedDEK
0x00009D     4   extra_passphrase_count : 00 00 00 00
0x0000A1     4   hybrid_768_count       : 00 00 00 00
0x0000A5     4   hybrid_1024_count      : 00 00 00 00
0x0000A9    66   ProtectedMetadata (mandatory TLV[50] + GCM_TAG[16])
0x0000EB     1   sender_present         : 00
──────── end header: 236 bytes ──────────────────────────────────────────────
0x0000EC     ∞   Payload (consecutive encrypted blocks)
─────────────────────────────────────────────────────────────────────────────
```

---

## 12. Password Change (rekey)

Only the primary symmetric slot changes. Extra passphrase slots, asymmetric
keyslots, ProtectedMetadata, and the payload are **unchanged**.

| Field | Change |
|---|---|
| `salt` | New random 16 bytes |
| `kek_nonce` | New random 12 bytes |
| `HeaderMAC` | Recomputed |
| `WrappedDEK` | Re-encrypted under new KEK |
| Extra passphrase slots | **Unchanged** |
| Hybrid keyslots | **Unchanged** |
| ProtectedMetadata | **Unchanged** |
| Payload | **Unchanged** |

Rekey is O(1) — the payload is never read or written.

---

## 13. User Identities

### Encryption keypair (`.key` file)

| Component                    | Size     | Storage                              |
|------------------------------|----------|--------------------------------------|
| X25519 private key           | 32 bytes | `ARSENIC-SECRET-KEY-1{bech32}`       |
| ML-KEM seed (`d‖z`)         | 64 bytes | `# mlkem-seed: ARSENIC-MLKEM-SEED-1…` |
| X25519 public key            | 32 bytes | `# public key: arsenic1…`            |
| ML-KEM-768 encapsulation key | 1184 bytes | `# mlkem-public-key: arsenic1m…`   |
| ML-KEM-768 decapsulation key | 2400 bytes | RAM only                           |
| ML-KEM-1024 EK               | 1568 bytes | Derived from same 64-byte seed     |

---

## 14. Security Properties

| Property | Mechanism |
|---|---|
| DEK confidentiality | AEAD under KEK (Argon2id) |
| Metadata confidentiality | AEAD under MetaKey = f(DEK) |
| Payload confidentiality | AEAD under per-block keys from DEK + index |
| Per-block integrity | 16-byte AEAD tag |
| Whole-file integrity | BLAKE3 Merkle root verified before any plaintext write |
| Block ordering | Index bound as AAD in each block AEAD |
| Header integrity | BLAKE3_keyed_hash(KEK, 77 public bytes) |
| Primary slot fast-fail | HeaderMAC before Argon2id for extra slots |
| DoS resistance | KDF params validated before any Argon2id |
| Quantum resistance — payload | 256-bit symmetric, Grover → 128 bits |
| Quantum resistance — L3 keyslots | ML-KEM-768 (NIST level 3) |
| Quantum resistance — L5 keyslots | ML-KEM-1024 (NIST level 5) |
| Defence in depth | Hybrid X25519+ML-KEM |
| Recipient anonymity | Keyslots do not reveal the recipient's public key |
| Compression privacy | Disabled by default; leaks size entropy when enabled |
| Memory erasure | `Secret<T>` zeroizes on drop |
