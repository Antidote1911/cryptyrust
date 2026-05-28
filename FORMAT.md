# Arsenic V2 — Cryptyrust file format

> This document describes the **Arsenic V2** format, the sole format produced and accepted by Cryptyrust.  
> File extension: `.arsn`

---

## Overview

An Arsenic V2 file consists of a fixed **256-byte header** followed by a sequence of **independently encrypted blocks**. The header contains all the metadata needed to decrypt the file — KDF parameters, nonces, and the encrypted DEK — and is authenticated with an HMAC-SHA256 MAC. The payload blocks are each authenticated with a Poly1305 tag. After decryption, a **BLAKE3 Merkle tree** over all encrypted blocks guarantees full-file integrity.

```
┌──────────────────────────────────┐
│   256-byte header (plaintext +   │
│   Serpent-GCM encrypted envelope)│
├──────────────────────────────────┤
│   Encrypted block 0              │  ← XChaCha20-Poly1305 + Poly1305 tag
├──────────────────────────────────┤
│   Encrypted block 1              │
├──────────────────────────────────┤
│   …                              │
└──────────────────────────────────┘
```

---

## 1. Header layout (256 bytes)

### 1.1 Plaintext public section — pre-MAC (bytes 0x00–0x4B, 76 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| `0x00` | 4 | Magic | `41 52 53 4E` ("ARSN") |
| `0x04` | 2 | Version | `00 02` |
| `0x06` | 1 | KDF ID | `01` = Argon2id |
| `0x07` | 1 | Header cipher ID | `02` = Serpent-256-GCM |
| `0x08` | 1 | Payload cipher ID | `03` = XChaCha20-Poly1305 |
| `0x09` | 1 | Compression ID | `00` = none |
| `0x0A` | 2 | Header total size | `00 01` = 256 (u16 LE) |
| `0x0C` | 16 | Argon2id salt | random, unique per file |
| `0x1C` | 4 | `t_cost` (iterations) | u32 LE |
| `0x20` | 4 | `m_cost` (memory, KB) | u32 LE |
| `0x24` | 4 | `p_cost` (parallelism) | u32 LE |
| `0x28` | 24 | File base nonce | random, unique per file |
| `0x40` | 12 | KEK nonce | random, unique per encryption |

### 1.2 Header MAC (bytes 0x4C–0x6B, 32 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x4C` | 32 | `HeaderMAC` | HMAC-SHA256 over bytes `0x00–0x4B` |

See [Section 4](#4-header-pre-authentication) for the MAC derivation.

### 1.3 Encrypted envelope (bytes 0x6C–0xCC, 97 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x6C` | 97 | `EncryptedEnvelope` | Serpent-256-GCM ciphertext (81 bytes plaintext + 16 bytes GCM tag) |

The **plaintext** of the envelope (81 bytes) contains:

| Offset (within plaintext) | Size | Field |
|---------------------------|------|-------|
| 0 | 32 | DEK (Data Encryption Key) |
| 32 | 32 | Merkle root (BLAKE3) |
| 64 | 8 | Original file size (u64 LE) |
| 72 | 8 | Compressed payload size (u64 LE) |
| 80 | 1 | Block size ID (`0x01` = 4 MB, `0x02` = 32 MB) |

The envelope is encrypted with `Serpent-256-GCM(key=KEK, nonce=KEK_nonce, aad=empty)`.

### 1.4 Padding (bytes 0xCD–0xFF, 51 bytes)

Zero bytes, reserved for future use.

---

## 2. Payload blocks

### 2.1 Block size selection

| File size | Block size | Block ID |
|-----------|-----------|----------|
| < 4 GiB | 4 MiB | `0x01` |
| ≥ 4 GiB | 32 MiB | `0x02` |

The last block is a partial block (fewer than `block_size` bytes of plaintext).

### 2.2 Per-block key and nonce derivation

Each block has its own 256-bit key and 192-bit nonce, derived from the DEK and the block index:

```
BlockKey_N   = BLAKE3_keyed_hash(key = DEK,  data = u64_LE(N))
BlockNonce_N = BLAKE3_derive_key("Arsenic V2 Block Nonce",
                                  file_base_nonce ‖ u64_LE(N))[0..24]
```

This derivation is deterministic and independent for each block, enabling **parallel encryption and decryption**.

### 2.3 Block encryption

Each block is encrypted with **XChaCha20-Poly1305**:

```
EncBlock_N = XChaCha20-Poly1305(
    key   = BlockKey_N,
    nonce = BlockNonce_N,
    aad   = u64_LE(N),       ← block index as AAD
    msg   = plaintext_block
)
```

The AAD binds the ciphertext to its position — a block cannot be silently reordered or replayed.

### 2.4 Encrypted block size

```
|EncBlock_N| = |plaintext_block_N| + 16   (Poly1305 tag)
```

---

## 3. Integrity — BLAKE3 Merkle tree

After all blocks are encrypted, a BLAKE3 hash of each encrypted block (including its Poly1305 tag) forms the leaves of a binary Merkle tree:

```
Leaf_N = BLAKE3(EncBlock_N)

Internal node = BLAKE3(left_child ‖ right_child)
Odd node promoted without hashing.

MerkleRoot = root of the tree over [Leaf_0, Leaf_1, …, Leaf_{N-1}]
```

The Merkle root is stored in the encrypted envelope (see [Section 1.3](#13-encrypted-envelope-bytes-0x6c0xcc-97-bytes)).

**On decryption**, all blocks are decrypted in parallel, the Merkle root is recomputed, and compared with the stored value. **Plaintext is written only after the full Merkle root matches.** Any block substitution, deletion, reordering, or truncation is detected.

---

## 4. Header pre-authentication

To prevent denial-of-service attacks based on forged `m_cost` (e.g. an attacker setting `m_cost = 8 GB`), the header is authenticated with a *cheap* HMAC-SHA256 before the expensive Argon2id derivation runs:

```
PreKey    = HMAC-SHA256(key = password,  data = salt)
HeaderMAC = HMAC-SHA256(key = PreKey,    data = header[0x00..0x4C])
```

`PreKey` is a single HMAC call — effectively free. If `HeaderMAC` does not match the stored value at `0x4C`, the file is rejected immediately without running Argon2id.

---

## 5. Key derivation

```
KEK = Argon2id(
    password = user password (UTF-8 bytes),
    salt     = header[0x0C..0x1C]  (16 random bytes),
    t        = t_cost,
    m        = m_cost  (KB),
    p        = p_cost,
    taglen   = 32
)
```

### Standard strength levels

| Name | t | m | p | Memory usage |
|------|---|---|---|---|
| Interactive (default) | 4 | 262 144 | 4 | 256 MiB |
| Sensitive | 12 | 1 048 576 | 4 | 1 GiB |

These values are stored plaintext in the header (`t_cost`, `m_cost`, `p_cost`) and are covered by the HeaderMAC.

---

## 6. Password change (rekey)

Rekeying rewrites **only the 256-byte header** without touching the payload:

1. Read the old header; verify `HeaderMAC` with the old password.
2. Derive old `KEK`; decrypt the envelope to recover the `DEK` and `MerkleRoot`.
3. Generate a fresh `salt` and `KEK_nonce`.
4. Derive new `KEK` = Argon2id(new\_password, new\_salt, same costs).
5. Re-encrypt the envelope under the new `KEK`.
6. Recompute `HeaderMAC` with the new password and new salt.
7. Write the new 256-byte header in-place.

The `DEK`, `MerkleRoot`, `file_base_nonce`, block sizes, and all payload bytes are unchanged.

### Crash safety

A 256-byte backup of the current header is written to `<file>.bak` and flushed to disk (`sync_all`) before step 7. On success the backup is deleted. If the process is interrupted:

- **Header magic (`ARSN`) intact** → the write completed before the crash; the backup is stale and will be silently replaced on the next rekey.
- **Header magic corrupted** → the write was interrupted mid-header; the backup is used to restore the original header automatically, and an error is returned asking the user to retry.

---

## 7. Complete hex example

Below is a minimal annotated header for a file encrypted with Interactive strength.

```
Offset  Bytes                                     Field
──────  ────────────────────────────────────────  ─────────────────────────────
0x00    41 52 53 4E                               Magic "ARSN"
0x04    00 02                                     Version 2
0x06    01                                        KDF = Argon2id
0x07    02                                        Header cipher = Serpent-GCM
0x08    03                                        Payload cipher = XChaCha20
0x09    00                                        Compression = none
0x0A    00 01                                     Header total size = 256 (LE)
0x0C    [16 random bytes]                         Argon2id salt
0x1C    04 00 00 00                               t_cost = 4
0x20    00 00 04 00 (= 0x00040000 = 262144 KB)    m_cost = 256 MiB
0x24    04 00 00 00                               p_cost = 4
0x28    [24 random bytes]                         File base nonce
0x40    [12 random bytes]                         KEK nonce
── MAC coverage ends here (76 bytes) ──────────────────────────────────────────
0x4C    [32 bytes]                                HeaderMAC (HMAC-SHA256)
0x6C    [97 bytes]                                Encrypted envelope
                                                  (DEK + MerkleRoot + sizes +
                                                   block ID + 16-byte GCM tag)
0xCD    [51 zero bytes]                           Padding
── End of header (256 bytes) ──────────────────────────────────────────────────
0x100   [block 0: plaintext_size + 16 bytes]      EncBlock_0
        [block 1: plaintext_size + 16 bytes]      EncBlock_1
        …
```

---

## 8. Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | XChaCha20-Poly1305 per block; Serpent-GCM for the DEK |
| Block integrity | Poly1305 tag per block |
| Full-file integrity | BLAKE3 Merkle root (verified before any output) |
| Block ordering | Block index bound as AAD |
| Header integrity | HMAC-SHA256 HeaderMAC |
| DoS resistance | Pre-auth MAC checked before Argon2id |
| Password change safety | Fresh salt + nonce; old payload untouched |
| Key material | `Secret<T>` zeroized on drop; DEK zeroized after use |
| Nonce reuse | Impossible: all nonces derived from random `file_base_nonce` + block index |
