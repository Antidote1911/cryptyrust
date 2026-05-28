# Arsenic V2 — Cryptyrust file format

> This document describes the **Arsenic V2** format, the sole format produced and accepted by Cryptyrust.  
> File extension: `.arsn`

---

## Overview

An Arsenic V2 file consists of a fixed **256-byte header** followed by a sequence of **independently encrypted blocks**. The header contains all the metadata needed to decrypt the file — KDF parameters, nonces, cipher algorithm identifiers, and the encrypted DEK — and is authenticated with an HMAC-SHA256 MAC computed before the expensive Argon2id derivation. The payload blocks are each authenticated with a 16-byte AEAD tag. After decryption, a **BLAKE3 Merkle tree** over all encrypted blocks guarantees full-file integrity before any plaintext is written.

```
┌────────────────────────────────────────────┐
│   256-byte header                          │
│     ├─ 76-byte public section (pre-MAC)    │
│     ├─ 32-byte HeaderMAC (HMAC-SHA256)     │
│     ├─ 97-byte encrypted envelope          │  ← header cipher (selectable)
│     └─ 51-byte zero padding                │
├────────────────────────────────────────────┤
│   Encrypted block 0                        │  ← payload cipher (selectable)
├────────────────────────────────────────────┤
│   Encrypted block 1                        │
├────────────────────────────────────────────┤
│   …                                        │
└────────────────────────────────────────────┘
```

Both the **header cipher** (used to encrypt the DEK envelope) and the **payload cipher** (used to encrypt each block) are independently selectable from three supported algorithms. Their IDs are stored at bytes `0x07` and `0x08` respectively and are covered by the `HeaderMAC`, so they cannot be silently altered.

---

## 1. Header layout (256 bytes)

### 1.1 Plaintext public section — pre-MAC (bytes `0x00`–`0x4B`, 76 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| `0x00` | 4 | Magic | `41 52 53 4E` ("ARSN") |
| `0x04` | 2 | Version | `00 02` |
| `0x06` | 1 | KDF ID | `01` = Argon2id |
| `0x07` | 1 | Header cipher ID | `02`/`03`/`04` — see [Section 3](#3-cipher-algorithms) |
| `0x08` | 1 | Payload cipher ID | `02`/`03`/`04` — see [Section 3](#3-cipher-algorithms) |
| `0x09` | 1 | Compression ID | `00` = none |
| `0x0A` | 2 | Header total size | `00 01` = 256 (u16 LE) |
| `0x0C` | 16 | Argon2id salt | random, unique per file |
| `0x1C` | 4 | `t_cost` (iterations) | u32 LE |
| `0x20` | 4 | `m_cost` (memory, KB) | u32 LE |
| `0x24` | 4 | `p_cost` (parallelism) | u32 LE |
| `0x28` | 24 | File base nonce | random, unique per file |
| `0x40` | 12 | KEK nonce | random, unique per encryption |

All 76 bytes (`0x00`–`0x4B`) are covered by the `HeaderMAC`.

### 1.2 Header MAC (bytes `0x4C`–`0x6B`, 32 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x4C` | 32 | `HeaderMAC` | HMAC-SHA256 over bytes `0x00`–`0x4B` |

See [Section 4](#4-header-pre-authentication) for the MAC derivation.

### 1.3 Encrypted envelope (bytes `0x6C`–`0xC2`, 97 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x6C` | 97 | `EncryptedEnvelope` | Header-cipher ciphertext (81 bytes plaintext + 16-byte AEAD tag) |

The algorithm used is the one identified by the **header cipher ID** at byte `0x07`. The **plaintext** of the envelope (81 bytes) contains:

| Offset (within plaintext) | Size | Field |
|---------------------------|------|-------|
| 0 | 32 | DEK (Data Encryption Key) |
| 32 | 32 | Merkle root (BLAKE3) |
| 64 | 8 | Original file size (u64 LE) |
| 72 | 8 | Compressed payload size (u64 LE) |
| 80 | 1 | Block size ID (`0x01` = 4 MiB, `0x02` = 32 MiB) |

The envelope is encrypted as:

```
EncryptedEnvelope = HeaderCipher(
    key   = KEK,
    nonce = KEK_nonce  (see nonce handling in Section 3),
    aad   = empty,
    msg   = envelope_plaintext
)
```

### 1.4 Padding (bytes `0xC3`–`0xFF`, 51 bytes)

Zero bytes, reserved for future use.

---

## 2. Payload blocks

### 2.1 Block size selection

| File size | Block size | Block size ID |
|-----------|-----------|---------------|
| < 4 GiB | 4 MiB | `0x01` |
| ≥ 4 GiB | 32 MiB | `0x02` |

The selected block size ID is stored in the encrypted envelope (byte 80 of the plaintext). The last block is a partial block.

### 2.2 Per-block key and nonce derivation

Each block has its own 256-bit key and nonce, derived deterministically from the DEK and the block index:

```
BlockKey_N   = BLAKE3_keyed_hash(key = DEK,  data = u64_LE(N))
BlockNonce_N = BLAKE3_derive_key("Arsenic V2 Block Nonce",
                                  file_base_nonce ‖ u64_LE(N))[0..24]
```

`BlockNonce_N` is always 24 bytes. Ciphers with a 12-byte nonce (Serpent-256-GCM, AES-256-GCM-SIV) consume only the first 12 bytes.

This derivation is fully independent per block, enabling **parallel encryption and decryption** via Rayon.

### 2.3 Block encryption

Each block is encrypted with the **payload cipher** identified at byte `0x08`:

```
EncBlock_N = PayloadCipher(
    key   = BlockKey_N,
    nonce = BlockNonce_N  (first 12 bytes for 12-byte-nonce ciphers),
    aad   = u64_LE(N),    ← block index as AAD
    msg   = plaintext_block_N
)
```

The AAD binds each ciphertext to its position — blocks cannot be reordered or replayed.

### 2.4 Encrypted block size

```
|EncBlock_N| = |plaintext_block_N| + 16   (AEAD tag, always 16 bytes)
```

---

## 3. Cipher algorithms

Both header and payload cipher IDs are stored in the plaintext public section at bytes `0x07` and `0x08`, covered by `HeaderMAC`. The two ciphers are **independently selectable**.

| ID | Algorithm | Nonce (bits) | Notes |
|----|-----------|-------------|-------|
| `0x02` | **Serpent-256-GCM** | 96 | Serpent-256 block cipher with NIST GCM mode; manual GHASH implementation. Default header cipher. |
| `0x03` | **XChaCha20-Poly1305** | 192 | 192-bit nonce eliminates nonce collision risk at scale. Default payload cipher. |
| `0x04` | **AES-256-GCM-SIV** | 96 | Nonce misuse-resistant GCM variant; safe even if a nonce is accidentally repeated. |

All three produce a **16-byte authentication tag**, so the encrypted envelope is always exactly 97 bytes and each encrypted block is always `plaintext_len + 16` bytes, regardless of algorithm.

### 3.1 Nonce handling

**Envelope (header cipher):**

The header stores a 12-byte `KEK_nonce` field at `0x40`–`0x4B`.

- **Serpent-256-GCM** and **AES-256-GCM-SIV** use the 12-byte nonce directly (both have 96-bit nonce sizes).
- **XChaCha20-Poly1305** requires a 192-bit (24-byte) nonce. The 12-byte stored value is BLAKE3-expanded to 24 bytes:

```
nonce24 = BLAKE3_derive_key(
    context = "Arsenic V2 KEK Nonce XChaCha20",
    data    = KEK_nonce ‖ 0x00×20   (12 bytes zero-padded to 32 bytes)
)[0..24]
```

This expansion is deterministic and reversible from the stored 12-byte field; no format change is needed.

**Payload blocks:**

`BlockNonce_N` is always derived as 24 bytes. Ciphers that use 96-bit nonces (Serpent-256-GCM, AES-256-GCM-SIV) consume `BlockNonce_N[0..12]`; XChaCha20-Poly1305 uses all 24 bytes.

---

## 4. Header pre-authentication

Before running the expensive Argon2id derivation, a cheap HMAC-SHA256 is verified to reject wrong passwords and detect header tampering without spending memory:

```
PreKey    = HMAC-SHA256(key = password,  data = salt)
HeaderMAC = HMAC-SHA256(key = PreKey,    data = header[0x00..0x4C])
```

`PreKey` costs one HMAC call — effectively free. A wrong password or forged header (including tampered cipher IDs or Argon2id cost parameters) is rejected immediately.

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

### Standard strength presets

| Name | t | m (KB) | p | Memory | Typical time |
|------|---|--------|---|--------|--------------|
| Interactive *(default)* | 4 | 262 144 | 4 | 256 MiB | ~1–3 s |
| Sensitive | 12 | 1 048 576 | 4 | 1 GiB | ~10–30 s |

The KDF parameters are stored in the plaintext public section and are covered by `HeaderMAC`, so they cannot be silently downgraded.

---

## 6. Integrity — BLAKE3 Merkle tree

After all blocks are encrypted, a BLAKE3 hash of each encrypted block (including its AEAD tag) forms a Merkle leaf:

```
Leaf_N        = BLAKE3(EncBlock_N)
InternalNode  = BLAKE3(left_child ‖ right_child)
Odd node promoted without hashing.
MerkleRoot    = root of tree over [Leaf_0, Leaf_1, …, Leaf_{N-1}]
```

The Merkle root is stored inside the encrypted envelope (bytes 32–63 of the plaintext). **On decryption, all blocks are decrypted in parallel, the Merkle root is recomputed, and compared with the stored value. No plaintext is written until the entire file passes verification.** Any block substitution, deletion, reordering, or truncation is detected.

---

## 7. Password change (rekey)

Rekeying rewrites **only the 256-byte header** without touching the payload:

1. Read the old header; verify `HeaderMAC` with the old password.
2. Derive old `KEK`; decrypt the envelope to recover `DEK`, `MerkleRoot`, and all envelope fields.
3. Generate a fresh `salt` and `KEK_nonce`.
4. Derive new `KEK` = Argon2id(new\_password, new\_salt, same costs).
5. Re-encrypt the envelope under the new `KEK` using the **same header cipher** (preserved from byte `0x07`).
6. Recompute `HeaderMAC` with the new password and new salt.
7. Write the new 256-byte header in-place.

The `DEK`, `MerkleRoot`, `file_base_nonce`, block size ID, payload cipher ID, and all payload bytes are unchanged.

### Crash safety

A 256-byte backup of the current header is written to `<file>.bak` and flushed to disk (`sync_all`) before step 7. On success the backup is deleted. If the process is interrupted:

- **Header magic (`ARSN`) intact** — the write completed; the backup is stale.
- **Header magic corrupted** — the write was interrupted mid-header; the backup is used to restore the original header automatically, and an error is returned asking the user to retry.

---

## 8. Complete hex example

Annotated header for a file encrypted with Interactive strength, Serpent-256-GCM header cipher, XChaCha20-Poly1305 payload cipher (the defaults):

```
Offset  Bytes                                          Field
──────  ─────────────────────────────────────────────  ─────────────────────────────────
0x00    41 52 53 4E                                    Magic "ARSN"
0x04    00 02                                          Version 2
0x06    01                                             KDF = Argon2id
0x07    02                                             Header cipher = Serpent-256-GCM
0x08    03                                             Payload cipher = XChaCha20-Poly1305
0x09    00                                             Compression = none
0x0A    00 01                                          Header total size = 256 (LE)
0x0C    [16 random bytes]                              Argon2id salt
0x1C    04 00 00 00                                    t_cost = 4
0x20    00 00 04 00  (= 0x00040000 = 262 144 KB)       m_cost = 256 MiB
0x24    04 00 00 00                                    p_cost = 4
0x28    [24 random bytes]                              File base nonce
0x40    [12 random bytes]                              KEK nonce (12 bytes)
── MAC coverage ends here (76 bytes, 0x00–0x4B) ────────────────────────────────────────
0x4C    [32 bytes]                                     HeaderMAC (HMAC-SHA256)
0x6C    [97 bytes]                                     Encrypted envelope
                                                       (DEK + MerkleRoot + sizes +
                                                        block ID + 16-byte AEAD tag)
0xC3    [51 zero bytes]                                Padding
── End of header (256 bytes, 0x100) ────────────────────────────────────────────────────
0x100   [block 0: plaintext_size_0 + 16 bytes]         EncBlock_0
        [block 1: plaintext_size_1 + 16 bytes]         EncBlock_1
        …
```

For an alternative cipher combination — e.g. AES-256-GCM-SIV header, Serpent-256-GCM payload — only bytes `0x07` and `0x08` differ (`04` and `02` respectively). The header size, envelope size, and block framing are identical for all cipher combinations.

---

## 9. Security properties

| Property | Mechanism |
|---|---|
| Confidentiality (envelope) | Selectable header cipher (Serpent-256-GCM / AES-256-GCM-SIV / XChaCha20-Poly1305) with a random 12-byte KEK nonce |
| Confidentiality (payload) | Selectable payload cipher (same three options) with per-block derived keys and nonces |
| Block integrity | 16-byte AEAD tag per block (Poly1305 or GHASH) |
| Full-file integrity | BLAKE3 Merkle root — verified before any output is written |
| Block ordering | Block index bound as AAD |
| Header integrity | HMAC-SHA256 `HeaderMAC` — covers cipher IDs and Argon2id cost parameters |
| DoS resistance | Pre-auth MAC checked before Argon2id; forged cost parameters rejected cheaply |
| Nonce reuse (blocks) | Impossible: `BlockNonce_N` derived from random `file_base_nonce` + block index |
| Nonce misuse resistance | AES-256-GCM-SIV option provides nonce misuse resistance |
| Password change safety | Fresh salt + KEK nonce; DEK and payload never re-encrypted |
| Key material erasure | `Secret<T>` zeroized on drop; DEK and KEK zeroized after use |
