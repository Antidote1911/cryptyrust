# Arsenic V1 — Cryptyrust File Format Specification

> **Version** `00 01`  ·  **Magic** `41 52 53 4E` ("ARSN")  ·  **Extension** `.arsn`

---

## Overview

An Arsenic V1 file is a **variable-length header** followed by a sequence of independently authenticated payload blocks. Every cryptographic decision is justified below.

```
┌─────────────────────────────────────────────┐  ← offset 0x00
│  Public section     76 bytes  (pre-MAC)     │  plaintext, integrity-protected
│  HeaderMAC          32 bytes  (HMAC-SHA256) │
│  WrappedDEK         48 bytes  (AEAD)        │  keyslot — changes on rekey
│  ProtectedMetadata  ≥ 76 bytes (AEAD + TLV) │  bound to DEK, never changes on rekey
└─────────────────────────────────────────────┘  ← offset = header_total_size (≥ 232)
┌─────────────────────────────────────────────┐
│  Block 0: [opt. u32 size] ciphertext + tag  │
│  Block 1: [opt. u32 size] ciphertext + tag  │
│  …                                          │
└─────────────────────────────────────────────┘
```

**Key design principles:**

- **DEK separation** — the Data Encryption Key is 32 random bytes, wrapped under the password-derived KEK. Changing a password only re-wraps the DEK; the payload is never re-encrypted.
- **LUKS-style keyslot** — the WrappedDEK (48 bytes) is the only thing that changes on rekey. ProtectedMetadata is encrypted under a key derived from the DEK, making it immutable from the password-change perspective.
- **Pre-authentication** — a cheap Argon2id pass produces a pre-auth key for the HeaderMAC, rejecting wrong passwords quickly while preventing fast offline oracle attacks.
- **Block-level parallelism** — each block has its own key and nonce derived from the DEK and block index, so encryption and decryption are fully parallelizable.
- **Full-file integrity** — a domain-separated BLAKE3 Merkle tree over all encrypted blocks is verified before any plaintext is written.

---

## 1. Header layout

The header has a **variable total size** stored at bytes `0x0A–0x0B`. The minimum is **232 bytes** (no optional metadata fields); optional TLV fields increase it.

### 1.1 Public section — pre-MAC (bytes `0x00`–`0x4B`, 76 bytes)

All 76 bytes are covered by the `HeaderMAC`. Fields cannot be silently altered, downgraded, or replayed.

| Offset  | Size | Field              | Value / Encoding                          |
|---------|------|--------------------|-------------------------------------------|
| `0x00`  | 4    | Magic              | `41 52 53 4E` — "ARSN" in ASCII           |
| `0x04`  | 2    | Version            | `00 01` — little-endian u16 = 1           |
| `0x06`  | 1    | KDF ID             | `01` = Argon2id (the only defined value)  |
| `0x07`  | 1    | Header cipher ID   | `02` / `03` / `04` — see §3              |
| `0x08`  | 1    | Payload cipher ID  | `02` / `03` / `04` — see §3              |
| `0x09`  | 1    | Compression ID     | `00` = none · `01` = zstd per-block       |
| `0x0A`  | 2    | `header_total_size`| u16 LE — total header size in bytes       |
| `0x0C`  | 16   | Argon2id salt      | 16 cryptographically random bytes         |
| `0x1C`  | 4    | `t_cost`           | u32 LE — Argon2id iteration count         |
| `0x20`  | 4    | `m_cost`           | u32 LE — Argon2id memory in KB            |
| `0x24`  | 4    | `p_cost`           | u32 LE — Argon2id parallelism             |
| `0x28`  | 24   | `file_base_nonce`  | 24 cryptographically random bytes         |
| `0x40`  | 12   | `kek_nonce`        | 12 cryptographically random bytes; seed for per-cipher nonce expansion (see §3.1) |

**Why `header_total_size` in the public section?** It is covered by the MAC, so an attacker cannot forge a larger header to trigger buffer over-reads. The parser allocates exactly `header_total_size` bytes after validating the MAC.

**Why store KDF parameters in plaintext?** The Argon2id parameters must be known before spending memory on derivation. Because they are under the MAC, a downgrade attack (inflated `m_cost` → DoS, or deflated `m_cost` → weakened key) is rejected without any Argon2id work.

### 1.2 Header MAC (bytes `0x4C`–`0x6B`, 32 bytes)

| Offset  | Size | Field       | Description                                     |
|---------|------|-------------|-------------------------------------------------|
| `0x4C`  | 32   | `HeaderMAC` | HMAC-SHA256(PreKey, header[`0x00`..`0x4C`])     |

See §4 for the derivation of `PreKey`.

**Public section + MAC subtotal: 108 bytes** (`PUB_HEADER_LEN = 0x6C`)

### 1.3 WrappedDEK (bytes `0x6C`–`0x97`, 48 bytes, fixed)

```
WrappedDEK = AEAD_hdr_cipher(
    key   = KEK,                          ← 32 bytes, derived via Argon2id
    nonce = derived from kek_nonce,       ← expanded per cipher (see §3.1)
    aad   = empty,
    msg   = DEK                           ← 32 random bytes
)
Output: 32 bytes ciphertext + 16 bytes AEAD tag = 48 bytes
```

**Why a separate keyslot?** This mirrors the LUKS2 / BitLocker / VeraCrypt architecture. The 48-byte WrappedDEK is the entire keyslot. On password change, only those 48 bytes are re-encrypted. ProtectedMetadata, which may contain large optional fields, is never touched.

**Why not include Merkle root and sizes in the keyslot?** Separating crypto-material (DEK) from authenticated metadata (Merkle root, sizes, options) keeps the keyslot minimal and constant-size, and allows the metadata to be encrypted under a key derived from the DEK rather than the password — making it immutable under rekey.

### 1.4 ProtectedMetadata (bytes `0x98`–`header_total_size - 1`, variable)

```
MetaKey   = BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)    → 32 bytes
MetaNonce = BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12] → 12 bytes

ProtectedMetadata = AEAD_hdr_cipher(
    key   = MetaKey,
    nonce = MetaNonce,
    aad   = empty,
    msg   = TLV_bytes            ← variable-length TLV
)
Output: len(TLV_bytes) + 16 bytes AEAD tag
```

**Why MetaKey = f(DEK) not f(password)?** The Merkle root is a function of the encrypted payload (which is keyed by the DEK). It never changes unless the payload changes. Binding ProtectedMetadata to the DEK — not to the password — means rekey never needs to touch it. MetaKey and MetaNonce are deterministic (DEK is unique per file), which is safe: the same (MetaKey, MetaNonce) pair always encrypts the same plaintext (the metadata doesn't change once written).

#### TLV encoding

Each record: `[tag: u8][length: u8][value: length bytes]`. Tags are processed left-to-right; first occurrence wins on duplicates; unknown tags are silently skipped (forward compatibility).

**Mandatory fields** (must be present; parser returns an error otherwise):

| Tag    | Length | Field             | Encoding          |
|--------|--------|-------------------|-------------------|
| `0x02` | 32     | BLAKE3 Merkle root| 32 raw bytes      |
| `0x03` | 8      | Original file size| u64 LE            |
| `0x04` | Compressed payload size| 8 | u64 LE (= original for uncompressed)|
| `0x05` | 1      | Block size ID     | `0x01` = 4 MiB · `0x02` = 32 MiB |
| `0x06` | 1      | Merkle algo ID    | `0x01` = Merkle v1 (see §6)       |

**Mandatory TLV plaintext size: 60 bytes** (5 × 2 bytes overhead + 32+8+8+1+1 bytes data)

**Optional fields** (silently skipped if absent; ignored on decryption by tools that don't understand them):

| Tag    | Max length | Field             | Encoding     |
|--------|------------|-------------------|--------------|
| `0x10` | 255        | Original filename | UTF-8        |
| `0x11` | 255        | Comment           | UTF-8        |
| `0x12` | 8          | Creation timestamp| u64 LE, unix |

**Why store metadata inside the encrypted envelope?** The content type (filename, comment) of a file is sensitive. Storing it encrypted and authenticated inside ProtectedMetadata means it cannot be read without the password and cannot be forged.

**Why TLV and not fixed offsets?** Fixed layouts cannot be extended without breaking decoders. TLV with unknown-tag skipping provides forward compatibility: a file written by a future version with new optional fields is still readable by older code that simply ignores the unknown tags.

#### Minimum ProtectedMetadata encrypted size

```
60 bytes TLV plaintext + 16 bytes AEAD tag = 76 bytes
```

#### Minimum total header size

```
108 (PUB_HEADER_LEN) + 48 (WrappedDEK) + 76 (ProtectedMetadata min) = 232 bytes
```

---

## 2. Payload blocks

### 2.1 Block size selection

| File size       | Block size | Block size ID |
|-----------------|------------|---------------|
| < 4 GiB         | 4 MiB      | `0x01`        |
| ≥ 4 GiB         | 32 MiB     | `0x02`        |

**Why large blocks?** Large blocks amortize the per-block BLAKE3 Merkle leaf computation and reduce the number of AEAD operations. The last block may be shorter than `block_size`.

**Why two sizes?** A 4 MiB block for files < 4 GiB keeps the Merkle tree shallow (at most ~1 000 leaves for a 4 GiB file). A 32 MiB block for large files prevents the tree from growing too deep.

### 2.2 Per-block key and nonce derivation

```
BlockKey_N   = BLAKE3_keyed_hash(key = DEK, data = u64_LE(N))          → 32 bytes
BlockNonce_N = BLAKE3_derive_key("Arsenic V1 Block Nonce",
                                  file_base_nonce ‖ u64_LE(N))[0..24]  → 24 bytes
```

`BlockNonce_N` is always derived as 24 bytes. AES-256-GCM-SIV (96-bit nonce) uses the first 12 bytes; Deoxys-II-256 (120-bit nonce) uses the first 15 bytes; XChaCha20-Poly1305 uses all 24.

**Why per-block key derivation?** Each block uses an independent key, so compromising one block's key gives no information about other blocks. The derivation is a single BLAKE3 call, making it fast enough to not be a bottleneck even with thousands of blocks.

**Why `file_base_nonce` in the block nonce?** `file_base_nonce` is 24 random bytes generated fresh per encryption. It ensures that even if the same DEK were reused (which cannot happen in practice since the DEK is always random), block nonces would still differ between files.

**Why separate key and nonce derivation?** Using the same primitive for both would require careful domain separation. BLAKE3_keyed_hash for keys and BLAKE3_derive_key (with a distinct context string) for nonces are already in disjoint output domains.

**Why all derivations are independent of each other?** Block N's key and nonce are computed solely from the DEK, block index, and file_base_nonce. This makes encryption and decryption **fully parallelizable** via Rayon — no block depends on any other block.

### 2.3 Block encryption — uncompressed (`compression_id = 0x00`)

```
EncBlock_N = PayloadCipher(
    key   = BlockKey_N,
    nonce = BlockNonce_N[0..12]   (AES-256-GCM-SIV)
          | BlockNonce_N[0..15]   (Deoxys-II-256)
          | BlockNonce_N[0..24]   (XChaCha20-Poly1305),
    aad   = u64_LE(N),           ← block index bound as Additional Authenticated Data
    msg   = plaintext_block_N    ← exactly block_size bytes except for the last block
)
Output: |plaintext_block_N| + 16 bytes (AEAD tag)
```

The AAD binds each ciphertext to its block position. Reordering or replaying a block (even with a valid AEAD tag from the same file) causes AEAD verification failure.

### 2.4 Block encryption — zstd per-block (`compression_id = 0x01`)

Each plaintext block (of exactly `block_size` bytes, except the last) is independently compressed before encryption:

```
CompressedBlock_N = zstd_compress(plaintext_block_N, level=3)
EncBlock_N        = PayloadCipher(
    key   = BlockKey_N,
    nonce = BlockNonce_N[0..12 | 0..15 | 0..24],   ← depends on cipher (see §2.2)
    aad   = u64_LE(N),
    msg   = CompressedBlock_N
)
```

Because `CompressedBlock_N` has a variable size, the on-disk layout prepends a 4-byte length:

```
On-disk layout per compressed block:
  [enc_size: u32 LE][EncBlock_N: enc_size bytes]
  where enc_size = |CompressedBlock_N| + 16
```

**Why per-block rather than whole-file compression?** Whole-file compression requires buffering the entire file in RAM before splitting into blocks. Per-block compression keeps memory usage at O(block_size) regardless of file size, and each (compress → encrypt) step is independent, preserving full Rayon parallelism.

**Why compress before encrypt?** Encrypting first would destroy the statistical patterns that compression algorithms exploit. The correct order is always compress → encrypt.

**Why zstd at level 3?** Level 3 is zstd's default: excellent ratio, very fast. The level is an encryption-time parameter; decompression does not need it, so only the compression algorithm ID is stored in the header.

**`compressed_size` field with per-block compression:** Since original-size blocks are independently compressed, `num_blocks = original_size.div_ceil(block_size)`. The `compressed_size` field equals `original_size` (blocks are based on the original plaintext; there is no single "total compressed size").

### 2.5 Block count derivation

**Uncompressed:** `num_blocks = compressed_size ÷ block_size` (ceiling division).

**Zstd per-block:** `num_blocks = original_size ÷ block_size` (ceiling division). Each block is then read using its u32 size prefix.

---

## 3. Cipher algorithms

Header cipher and payload cipher are **independently selectable**. Their IDs are stored at bytes `0x07` and `0x08` in the public section (covered by the HeaderMAC).

| ID     | Algorithm              | Nonce bits | Tag bytes | Notes                                         |
|--------|------------------------|------------|-----------|-----------------------------------------------|
| `0x02` | **Deoxys-II-256**      | 120        | 16        | Tweakable-block-cipher AEAD (RustCrypto). Default header cipher.           |
| `0x03` | **XChaCha20-Poly1305** | 192        | 16        | 192-bit nonce eliminates collision risk at scale. Default payload cipher.  |
| `0x04` | **AES-256-GCM-SIV**    | 96         | 16        | Nonce-misuse resistant: safe even if a nonce is accidentally reused.       |

**Why three ciphers?** Cryptographic agility allows users to hedge against future weaknesses: Deoxys-II-256 offers a tweakable-block-cipher alternative to AES-based schemes; XChaCha20 offers a software-friendly option; AES-GCM-SIV provides nonce-misuse resistance. All three produce 16-byte AEAD tags, so ciphertext sizes are algorithm-independent.

**Why not only one cipher?** Lock-in to a single algorithm creates concentration risk. Independent header and payload cipher selection allows mixing, e.g. Deoxys-II-256 on the header (containing the DEK) and XChaCha20 on the payload (bulk data).

**Why the header cipher also wraps ProtectedMetadata?** MetaKey is derived from the DEK using BLAKE3; the cipher used to encrypt ProtectedMetadata is the same as the header cipher. This keeps the format simple: one cipher ID controls both keyslot and metadata encryption.

### 3.1 Nonce handling

**WrappedDEK and ProtectedMetadata:** The 12-byte `kek_nonce` is stored in the public section.

- AES-256-GCM-SIV: use `kek_nonce` directly (96-bit nonce).
- Deoxys-II-256 (120-bit nonce): the 12-byte value is BLAKE3-expanded to 15 bytes:

```
nonce15 = BLAKE3_derive_key(
    context = "Arsenic V1 KEK Nonce DeoxysII256",
    data    = kek_nonce ‖ 0x00 × 20   (zero-padded to 32 bytes)
)[0..15]
```

- XChaCha20-Poly1305 (192-bit nonce): the 12-byte value is BLAKE3-expanded to 24 bytes:

```
nonce24 = BLAKE3_derive_key(
    context = "Arsenic V1 KEK Nonce XChaCha20",
    data    = kek_nonce ‖ 0x00 × 20   (zero-padded to 32 bytes)
)[0..24]
```

The MetaNonce (`MetaKey` encryption nonce) is derived separately: `BLAKE3_derive_key("Arsenic V1 Meta Nonce", DEK)[0..12]`.

**Payload blocks:** `BlockNonce_N` is always 24 bytes. AES-256-GCM-SIV consumes the first 12 bytes; Deoxys-II-256 consumes the first 15 bytes; XChaCha20-Poly1305 uses all 24.

---

## 4. Header pre-authentication

Before running the expensive full KEK derivation, Arsenic V1 verifies a HeaderMAC using a **tiny Argon2id** pre-authentication key:

```
PreKey    = Argon2id(password, salt, t=1, m=8 192 KB, p=1)
HeaderMAC = HMAC-SHA256(key = PreKey, data = header[0x00..0x4C])
```

A wrong password or forged header is rejected after ~2 ms — fast enough for user feedback, slow enough to prevent fast offline oracle attacks.

**Why not raw HMAC-SHA256(password, salt)?** A pure HMAC pre-key can be computed at ~20 billion attempts/second on a GPU (RTX 4090). That would turn the HeaderMAC into a completely bypassed brute-force oracle — an attacker would never need to run Argon2id at all. With tiny Argon2id at m = 8 MB, the attacker is limited to ~15 000 attempts/second — a ×1 300 000 reduction in throughput.

**Why not use the full KEK for the MAC?** The full KEK (t=4, m=256 MB) takes 1–3 seconds to derive. Using it for pre-auth would mean always paying the full KDF cost even when the password is simply wrong. With tiny Argon2id (~2 ms), wrong passwords are rejected quickly while still requiring real KDF work.

**Same salt, different key.** PreKey and KEK both use the 16-byte header salt, but Argon2id internally encodes t, m, and p into its output domain. Therefore `PreKey ≠ KEK` even with identical `(password, salt)` inputs.

**Why cover the full 76-byte public section?** The MAC covers all fields that affect decryption: magic, version, both cipher IDs, `header_total_size`, salt, Argon2id parameters, nonces. A forged or downgraded field of any kind causes the MAC to fail before the expensive Argon2id even starts.

---

## 5. Full key derivation (KEK)

```
KEK = Argon2id(
    password = user passphrase (UTF-8 bytes),
    salt     = header[0x0C..0x1C]   (16 random bytes),
    t        = t_cost               (u32, from header),
    m        = m_cost               (u32, KB, from header),
    p        = p_cost               (u32, from header),
    taglen   = 32
)
→ 32-byte KEK
```

**Standard presets:**

| Name             | t   | m (KB)    | p | RAM    | Typical time |
|------------------|-----|-----------|---|--------|--------------|
| Interactive *(default)* | 4 | 262 144 | 4 | 256 MiB | ~1–3 s  |
| Sensitive        | 12  | 1 048 576 | 4 | 1 GiB  | ~10–30 s     |

**Why Argon2id?** Argon2id is the winner of the Password Hashing Competition and the NIST recommendation. It is memory-hard (resists GPU/ASIC parallelism) and combines the data-dependent tradeoffs of Argon2d with the side-channel resistance of Argon2i.

**Why store KDF parameters in the file?** The parameters must be recoverable from the file alone, without out-of-band configuration. Because they are covered by the HeaderMAC, they cannot be silently downgraded.

---

## 6. Integrity — BLAKE3 Merkle tree v1

After all blocks are encrypted, a BLAKE3 Merkle tree is built over the ciphertexts. The Merkle root is stored inside ProtectedMetadata (tag `0x02`).

### Merkle v1 algorithm spec (algo ID `0x01`)

```
Leaf_N  = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1",  EncBlock_N)
Node(L, R) = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", L ‖ R)
           where L and R are 32-byte left and right child hashes

Tree construction (bottom-up):
  1. Compute Leaf_N for every block N.
  2. At each level, pair adjacent nodes: Node(leaves[i], leaves[i+1]).
  3. If the count is odd, the last node is promoted to the next level unchanged.
  4. Repeat until one node remains: the Merkle root.

Special cases:
  0 blocks (empty file): root = [0x00 × 32]
  1 block:               root = Leaf_0
```

**On decryption:** all blocks are decrypted in parallel; the Merkle root is recomputed from the resulting ciphertexts; the recomputed root is compared to the stored root. **No plaintext is written until the entire file passes verification.**

**Why domain separation (derive_key instead of bare hash)?** Without it, a leaf hash and an internal node hash are in the same output domain. An attacker who can craft a 64-byte block `B = left ‖ right` could arrange `BLAKE3(B) = Node(left, right)`, creating a second-preimage confusion between leaf and node. `BLAKE3_derive_key` applies a domain string that makes the leaf and node output domains strictly disjoint.

**Why a Merkle tree rather than a single hash over all blocks?** The Merkle tree binds the order and integrity of individual blocks. An attacker cannot substitute a valid block from one file into another file's position (the block index is bound as AAD in the AEAD, not in the Merkle tree, providing two independent layers of ordering protection). Additionally, the Merkle root is computed over ciphertext (including AEAD tags), so any bit flip in any block — including the tag — changes the leaf hash.

**Why store the root in ProtectedMetadata (not in the public section)?** The Merkle root reveals structural information about the file (e.g., whether two files have identical content). Storing it inside the encrypted ProtectedMetadata keeps it confidential.

**Why BLAKE3?** BLAKE3 is fast (outperforms SHA-2 and SHA-3 on modern hardware), parallelizable, and has a clean, audited specification. The `derive_key` API provides domain separation without additional hashing overhead.

---

## 7. Password change (rekey)

Rekey is a **LUKS-style keyslot replacement**: only the 48-byte WrappedDEK changes. ProtectedMetadata is copied byte-for-byte without decryption or re-encryption.

**Steps:**

1. Read the full header (exactly `header_total_size` bytes).
2. Verify `HeaderMAC` with the old password (tiny Argon2id → HMAC-SHA256).
3. Derive old KEK with full Argon2id.
4. Decrypt `WrappedDEK` with old KEK → recover the 32-byte DEK.
5. Generate fresh `new_salt` (16 bytes) and `new_kek_nonce` (12 bytes).
6. Derive new KEK = Argon2id(new_password, new_salt, same t/m/p).
7. Encrypt DEK with new KEK → `new_WrappedDEK` (48 bytes).
8. Assemble new header: updated public section + new HeaderMAC + `new_WrappedDEK` + **original ProtectedMetadata bytes unchanged**.
9. Write the new header in-place (same `header_total_size`).

**What is unchanged after rekey:** DEK, Merkle root, file_base_nonce, payload bytes, all TLV metadata, `header_total_size`, cipher IDs.

**Why does ProtectedMetadata not need re-encryption?** MetaKey = BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK). Since the DEK is unchanged, MetaKey is unchanged, and the already-encrypted ProtectedMetadata bytes remain valid under the unchanged MetaKey.

### Crash safety

A backup copy of the current header is written to `<file>.bak` and flushed to disk (`sync_all`) before the in-place write begins. On success the backup is deleted.

If the process is interrupted:
- **"ARSN" magic intact** → the new header was written completely; the backup is stale.
- **"ARSN" magic corrupted** → the write was interrupted mid-header; the backup is used to restore the original header automatically, and an error is returned asking the user to retry.

---

## 8. Precise byte-level diagram

### Full header (minimum, no optional fields)

```
Byte offset   Size   Section                   Content
─────────────────────────────────────────────────────────────────────
0x000  00–03     4   Magic                     41 52 53 4E ("ARSN")
0x004  04–05     2   Version                   00 01 (LE u16 = 1)
0x006  06        1   KDF ID                    01 (Argon2id)
0x007  07        1   Header cipher ID          02/03/04
0x008  08        1   Payload cipher ID         02/03/04
0x009  09        1   Compression ID            00/01
0x00A  0A–0B     2   header_total_size         E8 00 (LE = 232, minimum)
0x00C  0C–1B    16   Argon2id salt             [16 random bytes]
0x01C  1C–1F     4   t_cost                    04 00 00 00 (Interactive)
0x020  20–23     4   m_cost (KB)               00 00 04 00 (262 144 KB = 256 MiB)
0x024  24–27     4   p_cost                    04 00 00 00
0x028  28–3F    24   file_base_nonce           [24 random bytes]
0x040  40–4B    12   kek_nonce                 [12 random bytes]
──────────────────────────────────────────── pre-MAC = 76 bytes (0x00–0x4B) ──────
0x04C  4C–6B    32   HeaderMAC                 HMAC-SHA256(PreKey, header[0..0x4C])
─────────────────────────────────────────── PUB_HEADER_LEN = 108 bytes ──────────
0x06C  6C–97    48   WrappedDEK                AEAD_hdr(KEK, nonce_from(kek_nonce), DEK)
                                               [32 bytes ciphertext + 16 bytes tag]
──────────────────────────────────── ProtectedMetadata (min = 76 enc bytes) ─────
0x098  98–C3    76   ProtectedMetadata         AEAD_hdr(MetaKey, MetaNonce, TLV)
                                               TLV plaintext (60 bytes mandatory):
                                                 02 20 [32B Merkle root]
                                                 03 08 [8B original_size LE]
                                                 04 08 [8B compressed_size LE]
                                                 05 01 [01 block_size_id]
                                                 06 01 [01 merkle_algo_id]
                                               + 16 bytes AEAD tag
────────────────────────────────────────── total header = 232 bytes (0xE8) ──────
0x0E8  …        ∞   Payload blocks            [uncompressed or u32-prefixed zstd]
```

### Per-block layout (uncompressed)

```
[ciphertext: plaintext_len bytes][AEAD tag: 16 bytes]
= plaintext_len + 16 bytes total
```

### Per-block layout (zstd, compression_id = 0x01)

```
[enc_size: u32 LE][ciphertext: compressed_len bytes][AEAD tag: 16 bytes]
= 4 + compressed_len + 16 bytes total
where enc_size = compressed_len + 16
```

---

## 9. Key material erasure

All sensitive values (`DEK`, `KEK`, `PreKey`, `MetaKey`) are stored in `Secret<T>` wrappers that call `zeroize` on drop, overwriting the memory with zeros before deallocation. BLAKE3-derived intermediate values that exist as temporary stack allocations are also zeroized.

---

## 10. Security properties

| Property                          | Mechanism                                                                  |
|-----------------------------------|----------------------------------------------------------------------------|
| Confidentiality — DEK             | AEAD under KEK (Argon2id-derived); random 32-byte DEK, random kek_nonce   |
| Confidentiality — metadata        | AEAD under MetaKey derived from DEK; MetaNonce deterministic per DEK       |
| Confidentiality — payload         | AEAD under per-block keys derived from DEK + block index                   |
| Block integrity                   | 16-byte AEAD tag per block                                                 |
| Full-file integrity               | BLAKE3 Merkle v1 root; verified before any plaintext is written            |
| Block ordering                    | Block index bound as AAD in every block AEAD                               |
| Header integrity                  | HMAC-SHA256 over all 76 public bytes; covers cipher IDs and KDF params     |
| Fast-oracle resistance            | Pre-auth PreKey derived via tiny Argon2id (~15 000 H/s on GPU)             |
| DoS resistance                    | Forged KDF params covered by MAC; rejected without running Argon2id        |
| Nonce reuse — blocks              | Impossible: `BlockNonce_N = f(file_base_nonce, N)`; both are unique        |
| Nonce misuse resistance           | AES-256-GCM-SIV option provides nonce-misuse resistance for header/payload |
| Password change safety            | DEK unchanged; only 48-byte keyslot re-encrypted; payload untouched        |
| Metadata confidentiality          | Filename, comment, timestamp encrypted inside ProtectedMetadata            |
| Second-preimage (Merkle)          | Domain separation: leaf and node hashes in disjoint BLAKE3 output domains  |
| Key material erasure              | `Secret<T>` zeroized on drop throughout                                    |
