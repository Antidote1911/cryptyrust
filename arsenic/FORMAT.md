# Arsenic V2 File Format — Specification

> **Format version**: `[0x00, 0x02]`
> **Magic**: `41 52 53 4E` ("ARSN")
> **Usual extension**: `.arsn` (binary) · `.arsn.armor` (ASCII-armored)
> All multi-byte integers are **little-endian**.

V2 is not compatible with V1: a V1 file is rejected with *"Unsupported file
format version"*. The differences are listed in §13.

---

## 1. Overview

```
┌───────────────────────────────────────────────┐  offset 0
│  Header  (variable size)                      │  length = header_total_size
├───────────────────────────────────────────────┤  offset header_total_size
│  Payload (consecutive AEAD blocks, ≥ 1)       │  until end of file
└───────────────────────────────────────────────┘
```

Key hierarchy:

```
password ──Argon2id──► master ──┬─► slot wrapping key ──AEAD──► DEK
                                └─► slot check key
keypair ──X25519 + ML-KEM──► hybrid wrapping key ──AEAD──► DEK

DEK (32 random bytes, one per file)
 ├─► header MAC key      BLAKE3_derive_key("Arsenic V2 header MAC key", DEK)
 ├─► metadata key        BLAKE3_derive_key("Arsenic V2 metadata key",   DEK)
 └─► payload key         BLAKE3_derive_key("Arsenic V2 payload key",    DEK)
```

Every key slot (password or keypair) wraps the **same DEK**. No key is ever
used for two purposes.

---

## 2. Header layout

```
Public parameters                 65 bytes
Password slots                    u32 count K (0–16), then K × 92 bytes
ML-KEM-768 keyslots               u32 count N, then N × 1180 bytes
ML-KEM-1024 keyslots              u32 count M, then M × 1660 bytes   (N + M ≤ 256)
Protected metadata                u32 length L, then L bytes
Sender                            1 byte marker [+ identity]
HeaderMAC                         32 bytes
```

A reader must reject a header with any out-of-range count, a short field, an
unknown marker, or bytes left over before the MAC.

### 2.1 Public parameters (65 bytes)

```
Offset  Size  Field
0x00      4   magic               41 52 53 4E
0x04      2   version             00 02
0x06      1   kdf_id              01 = Argon2id
0x07      1   hdr_cipher_id       cipher of key slots and metadata (§7)
0x08      1   pld_cipher_id       cipher of payload blocks (§7)
0x09      4   header_total_size   u32, whole header including the MAC
0x0D     16   salt                Argon2id salt, shared by all password slots
0x1D      4   t_cost              Argon2id passes          1 … 64
0x21      4   m_cost              Argon2id memory in KiB   8·p_cost … 4 GiB
0x25      4   p_cost              Argon2id lanes           1 … 16
0x29     24   file_base_nonce     random, base of the block nonces
```

The Argon2id limits are enforced **when encrypting** (so no undecryptable
file is produced) and before any KDF run when decrypting (so a hostile header
cannot request unbounded work). `header_total_size` must be in
`[155, 64 MiB]`.

### 2.2 Password slot (92 bytes)

```
password'  = NFC(password)                      Unicode normalization
master     = Argon2id(password', salt, t_cost, m_cost, p_cost)        32 bytes
wrap_key   = BLAKE3_derive_key("Arsenic V2 password slot wrapping key", master)
check_key  = BLAKE3_derive_key("Arsenic V2 password slot check key",    master)

Offset  Size  Field
  0      12   nonce         random
 12      48   wrapped_dek   AEAD_hdr(wrap_key, nonce, "arsenic-v2-password-wrapped-dek", DEK)
 60      32   check         BLAKE3_keyed_hash(check_key, nonce)
```

* All slots are equal: there is no "primary" password. Any password can add,
  change or remove a password or a recipient.
* The salt is shared, so testing a password costs **one** Argon2id run
  whatever K is; `check` then tells which slot (if any) it belongs to, in
  constant time, before any AEAD attempt.
* `check` commits the slot to one key (the AEADs alone are not
  key-committing).
* K may be 0: a file encrypted for recipients only has no password slot.
* A file must keep at least one key slot (K + N + M ≥ 1).

### 2.3 Hybrid keyslots

ML-KEM-768 slot (1180 bytes) — the ML-KEM-1024 slot (1660 bytes) is identical
with a 1568-byte ciphertext.

```
Offset  Size  Field
  0      32   ephemeral_x25519    ephemeral X25519 public key
 32    1088   mlkem_ciphertext    ML-KEM encapsulation for the recipient
1120     12   kek_nonce           random
1132     48   wrapped_dek         AEAD_hdr(wrapping_key, kek_nonce, "arsenic-v2-hybrid-wrapped-dek", DEK)

wrapping_key = BLAKE3_derive_key(context,
                 ephemeral_x25519 || mlkem_ciphertext || ss_x25519 || ss_mlkem)
context      = "Arsenic V2 hybrid KEM 768"  or  "Arsenic V2 hybrid KEM 1024"
```

Slots are numbered with the 768 slots first, then the 1024 slots. A slot does
not reveal the recipient's public key. A recipient public key that is not a
valid ML-KEM key is refused at encryption time.

### 2.4 Protected metadata

```
protected_meta = nonce(12, random) || AEAD_hdr(metadata_key, nonce, "arsenic-v2-protected-meta", TLV)
```

TLV entries are `tag(1) || length(1) || value`:

| Tag    | Length | Value                                             |
|--------|--------|---------------------------------------------------|
| `0x03` | 8      | OriginalSize — size of the uncompressed plaintext |
| `0x05` | 1      | BlockSizeId (§5)                                  |
| `0x07` | 1      | CompressAlgoId: `0x01` = zstd. Absent = none      |
| `0x10` | ≤ 255  | Filename (UTF-8)                                  |
| `0x11` | ≤ 255  | Comment (UTF-8)                                   |
| `0x12` | 8      | TimestampSecs                                     |

`0x03` and `0x05` are mandatory. Entries may appear in any order (writers emit
them in the order of the table). A duplicate field, an invalid length, invalid
UTF-8 or an unknown compression algorithm is an error. An unknown tag below
`0x80` is an error (it would change how the file is read); an unknown tag at
or above `0x80` is ignored. Text longer than 255 bytes is cut on a character
boundary when writing.

### 2.5 Sender

```
0x00                                   no sender
0x01 || name_len(u16) || name || x25519_pk(32) || mlkem_pk(1184)      name_len ≤ 255
```

Stored in clear, so it can be read without any key — but it is only
trustworthy after a successful decryption, which verifies the HeaderMAC that
covers it. Even then it remains a claim made by whoever encrypted the file,
not a proof of identity.

### 2.6 HeaderMAC (last 32 bytes)

```
HeaderMAC = BLAKE3_keyed_hash(header_mac_key, header[0 .. header_total_size − 32])
```

It covers **every** byte of the header and is keyed from the DEK, so it is
verified by any reader, whether the DEK came from a password or a keypair.
Changing, adding, removing or reordering a slot, the metadata or the sender
is detected.

---

## 3. Header size

```
header_total_size = 65
                  + 4 + K × 92
                  + 4 + N × 1180
                  + 4 + M × 1660
                  + 4 + 12 + len(TLV) + 16
                  + 1 [+ 2 + len(name) + 32 + 1184]
                  + 32
```

| Configuration                         | Header size |
|---------------------------------------|-------------|
| Minimum (no slot, no sender)          | 155 bytes   |
| One password                          | 247 bytes   |
| + one more password                   | + 92        |
| + one ML-KEM-768 recipient            | + 1180      |
| + one ML-KEM-1024 recipient           | + 1660      |
| + zstd                                | + 3         |
| + sender "alice"                      | + 1223      |

---

## 4. Payload

A sequence of independent AEAD blocks. There is always at least one block: an
empty file is a single block of 0 plaintext bytes (16 bytes on disk).

```
payload_key ← BLAKE3_derive_key("Arsenic V2 payload key", DEK)

for block i (0-based), final = 1 for the last block, else 0:
  key_i   = BLAKE3_keyed_hash(payload_key, i as u64 LE)
  aad_i   = i as u64 LE || final                                  9 bytes
  nonce_i = BLAKE3_derive_key("Arsenic V2 block nonce", file_base_nonce || aad_i)[0..24]
  block_i = AEAD_pld(key_i, nonce_i, aad_i, plaintext_i)          plaintext + 16-byte tag
```

Every block except the last holds exactly `block_size` plaintext bytes; the
last holds 0 … `block_size`.

A reader derives the number of blocks from the payload length and decrypts
the last one with `final = 1`. Consequently:

| Modification                       | Result                                  |
|------------------------------------|-----------------------------------------|
| A block altered                    | its tag fails                           |
| Blocks reordered or duplicated     | index in nonce and AAD → tag fails      |
| File truncated on a block boundary | new last block is not `final` → fails   |
| Data appended                      | old last block is no longer last → fails|
| Whole payload removed              | no block at all → rejected              |

Finally the number of plaintext bytes written must equal `OriginalSize`.

Decryption is a single pass. Blocks are released as they authenticate, so a
failure on a later block is reported after earlier plaintext was written: the
caller must discard the output on error.

### 4.1 Compression

With tag `0x07` present, the blocks carry a zstd stream of the plaintext.
Both directions are streaming. When decompressing, output is capped at
`OriginalSize` (authenticated), which bounds a hostile compressed payload.

> Compression leaks information about the plaintext through the ciphertext
> size. It is off by default.

---

## 5. Block size

| BlockSizeId | Plaintext per block | Chosen when the input is |
|-------------|---------------------|--------------------------|
| `0x01`      | 4 MiB               | smaller than 4 GiB       |
| `0x02`      | 32 MiB              | 4 GiB or larger          |

---

## 6. Random access

One block can be decrypted alone: the header is authenticated, then the block
at `header_total_size + i × (block_size + 16)`. Whether it is the final block
follows from the file length. Not available for compressed files.

---

## 7. AEAD ciphers

| id     | Algorithm           | Nonce used                                     |
|--------|---------------------|------------------------------------------------|
| `0x02` | Deoxys-II-256       | 15 bytes                                       |
| `0x03` | XChaCha20-Poly1305  | 24 bytes                                       |
| `0x04` | AES-256-GCM-SIV     | 12 bytes                                       |

All produce a 16-byte tag. Header operations store a 12-byte nonce, used as
is by AES-256-GCM-SIV and BLAKE3-expanded to 15 or 24 bytes for the two
others. Payload blocks use the first 12, 15 or all 24 bytes of `nonce_i`.

---

## 8. ASCII armor

A transport encoding of the binary file; it does not change the format.

```
-----BEGIN ARSENIC ENCRYPTED FILE-----
<base64, 64-character lines>
-----END ARSENIC ENCRYPTED FILE-----
```

---

## 9. Maintenance operations

All of them authenticate with a password of the file, verify the HeaderMAC,
edit the slot list, and compute a new HeaderMAC with the DEK. The payload is
never read or rewritten by the cryptographic code.

| Operation         | Change                                                     |
|-------------------|------------------------------------------------------------|
| Change a password | its slot is replaced (new nonce, wrapped DEK, check)       |
| Add a password    | one slot appended; refused if it already opens the file    |
| Remove a password | its slot removed; refused if it is the last key slot       |
| Add a recipient   | one 768 or 1024 keyslot appended                           |
| Remove a recipient| the keyslot at the given index removed                     |

The salt, the Argon2id parameters and the **DEK never change**. Changing or
removing a password therefore does not protect a copy of the file made
earlier: whoever knew the old password can still open that old copy. Revoking
a compromised password means decrypting and encrypting again, which creates a
new DEK and a new salt.

A file without any password slot cannot be edited.

---

## 10. Minimal file (one password, empty plaintext)

```
Offset   Size  Content
0x0000     4   magic               41 52 53 4E
0x0004     2   version             00 02
0x0006     1   kdf_id              01
0x0007     1   hdr_cipher_id
0x0008     1   pld_cipher_id
0x0009     4   header_total_size   F7 00 00 00  (247)
0x000D    16   salt
0x001D    12   t_cost, m_cost, p_cost
0x0029    24   file_base_nonce
0x0041     4   password slot count 01 00 00 00
0x0045    92   password slot
0x00A1     4   768 keyslot count   00 00 00 00
0x00A5     4   1024 keyslot count  00 00 00 00
0x00A9     4   metadata length     29 00 00 00  (41)
0x00AD    41   nonce(12) + TLV(13) + tag(16)
0x00D6     1   sender marker       00
0x00D7    32   HeaderMAC
0x00F7    16   payload: one empty final block (tag only)
```

---

## 11. Identities

| Component                    | Size       | Storage                               |
|------------------------------|------------|---------------------------------------|
| X25519 private key           | 32 bytes   | `ARSENIC-SECRET-KEY-1…`               |
| ML-KEM seed (`d‖z`)          | 64 bytes   | `# mlkem-seed: ARSENIC-MLKEM-SEED-1…` |
| X25519 public key            | 32 bytes   | `# public key: arsenic1…`             |
| ML-KEM-768 encapsulation key | 1184 bytes | `# mlkem-public-key: arsenic1m…`      |
| ML-KEM-1024 encapsulation key| 1568 bytes | derived from the same seed            |

---

## 12. Security properties

| Property                     | Mechanism                                                     |
|------------------------------|---------------------------------------------------------------|
| Password hardening           | Argon2id, bounded parameters, NFC-normalized password         |
| DEK confidentiality          | AEAD under a password- or keypair-derived wrapping key        |
| Key separation               | distinct BLAKE3-derived subkeys for wrap, check, MAC, metadata, payload |
| Header integrity             | BLAKE3 MAC over the whole header, keyed from the DEK          |
| Slot key commitment          | `check` tag (passwords); HeaderMAC under the DEK (all slots)  |
| Block integrity and order    | AEAD tag, index in nonce and AAD                              |
| Truncation / extension       | `final` flag in nonce and AAD, at least one block, size check |
| Metadata confidentiality     | AEAD under the metadata key, random nonce                     |
| Decompression bound          | output capped at the authenticated `OriginalSize`             |
| Post-quantum key exchange    | X25519 + ML-KEM-768 or ML-KEM-1024, both secrets hashed       |
| Recipient anonymity          | keyslots do not contain the recipient's public key            |
| Memory hygiene               | keys held in zeroizing containers, plaintext buffers wiped    |

Not provided: plaintext length hiding (the ciphertext length reveals it, to
within the compression ratio if compression is on), sender authentication,
and forward secrecy for a file whose password or key later leaks.

---

## 13. Changes from V1

| Area            | V1                                               | V2                                              |
|-----------------|--------------------------------------------------|-------------------------------------------------|
| Header MAC      | 77 public bytes, keyed by the primary password   | whole header, keyed from the DEK                |
| Password slots  | one primary + up to 15 extra (own salt, no MAC)  | up to 16 equal slots, shared salt, check tag    |
| No-password file| impossible (random throwaway password)           | zero password slots                             |
| Key use         | KEK both MAC key and AEAD key                    | separate derived subkeys                        |
| Payload integrity| BLAKE3 Merkle root, two passes                  | `final` flag in each block, one pass            |
| Empty file      | zero blocks                                      | one empty authenticated block                   |
| Metadata nonce  | derived from the DEK                             | random, stored                                  |
| Metadata TLV    | extended lengths, unknown tags ignored           | 1-byte lengths, critical/ignorable tag ranges   |
| Sender region   | unauthenticated                                  | covered by the HeaderMAC                        |
| KDF limits      | checked when decrypting only                     | checked when encrypting too                     |
| Password text   | raw bytes                                        | Unicode NFC                                     |
| Compression     | whole file in memory, unbounded decompression    | streaming, capped at `OriginalSize`             |
| Processing      | sequential                                       | blocks in parallel, bounded memory window       |
