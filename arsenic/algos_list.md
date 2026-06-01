> [Version française](algos_list_fr.md)

# Cryptographic Algorithms Used in Arsenic

This document lists and explains every cryptographic algorithm used in the `arsenic` library. Algorithms are grouped by functional role.

---

## Table of Contents

1. [Password-based Key Derivation — Argon2id](#1-argon2id)
2. [Header MAC — HMAC-SHA256](#2-hmac-sha256)
3. [Hash Functions and Internal Derivation — BLAKE3](#3-blake3)
4. [Authenticated Ciphers (AEAD)](#4-aead-ciphers)
   - 4a. Deoxys-II-256
   - 4b. XChaCha20-Poly1305
   - 4c. AES-256-GCM-SIV
5. [Post-quantum Hybrid KEM](#5-post-quantum-hybrid-kem)
   - 5a. X25519 (ECDH)
   - 5b. ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203)
6. [Merkle Tree](#6-merkle-tree)
7. [Key Encoding — Bech32](#7-bech32)
8. [Secure Memory Erasure — Zeroize](#8-zeroize)
9. [Role Overview and Interactions](#9-overview)

---

## 1. Argon2id

**Role:** derive a cryptographic key from a human password.

**Standard:** winner of the Password Hashing Competition (PHC) 2015,
recommended by NIST SP 800-63B and OWASP.

**Why Argon2id and not bcrypt / scrypt / PBKDF2?**

| Property | Argon2id | bcrypt | scrypt | PBKDF2 |
|---|---|---|---|---|
| GPU resistance | ✓✓ (memory + time) | ✓ | ✓✓ | ✗ |
| FPGA/ASIC resistance | ✓✓ | ✗ | ✓ | ✗ |
| Side-channel protection | ✓ (hybrid d) | ✗ | ✗ | ✗ |
| Configurability | memory, time, parallelism | time only | memory + time | time only |

Argon2id combines Argon2d (resistant to GPU side-channel attacks) and
Argon2i (resistant to time-memory trade-offs). The `id` variant is the
best default.

**Two distinct uses in Arsenic:**

### 1a. Pre-authentication (fixed parameters)

Used to generate the `PreKey` for verifying the `HeaderMAC` **before**
launching the main derivation.

```
t_cost = 1         (1 iteration)
m_cost = 8 192 KB  (8 MiB)
p_cost = 1         (1 thread)
output = 32 bytes
```

Typical cost: **~2 ms**. Sufficient to reject a wrong password
quickly (~15 000 attempts/s on GPU, vs. >10⁹/s for a bare HMAC-SHA256),
without exposing a zero-cost oracle.

### 1b. Main KEK derivation (configurable parameters)

Generates the KEK (Key Encryption Key) that protects the DEK.

| Preset | `t_cost` | `m_cost` | `p_cost` | RAM | Typical time |
|---|---|---|---|---|---|
| **Interactive** *(default)* | 4 | 262 144 KB | 4 | 256 MiB | ~1–3 s |
| **Sensitive** | 12 | 1 048 576 KB | 4 | 1 GiB | ~10–30 s |

Parameters are stored in plaintext in the file header, allowing
decryption without external configuration. They are covered by the
`HeaderMAC` and cannot be silently tampered with.

**Post-quantum resistance:** Argon2id is a classical one-way function.
Grover's algorithm reduces the security of a 256-bit symmetric key
to 128 effective bits — Argon2id with a 32-byte (256-bit) output
therefore remains secure against quantum computers.

---

## 2. HMAC-SHA256

**Role:** authenticate the file's public header (`HeaderMAC`).

**Standard:** RFC 2104, NIST FIPS 198-1.

**Why SHA-256 and not SHA-3 / BLAKE3?**
SHA-256 is ubiquitous, hardware-accelerated, and its use in
HMAC is well-analysed. BLAKE3 could have been used, but SHA-256 offers
better interoperability and wider compatibility with external verification tools.

**Construction:**

```
KEK = Argon2id(password, salt, t_cost, m_cost, p_cost) → 32 bytes

HeaderMAC = HMAC-SHA256(
    key  = KEK[32],
    msg  = pre_mac[77 bytes]   ← all of public header except the MAC itself
)
```

**What the MAC protects:**
- Magic bytes and format version
- Cipher identifiers (header and payload)
- `header_total_size`
- Argon2id salt and KDF parameters (`t`, `m`, `p`)
- `file_base_nonce` and `kek_nonce`

**Security property:** the HeaderMAC key is the full KEK derived with the
configured Argon2id parameters (Interactive: 256 MiB / Sensitive: 1 GiB).
An offline attacker must pay the full KDF cost per password attempt —
there is no faster oracle. A wrong password produces a wrong KEK which
fails the HMAC check before any AEAD decryption is attempted.

**DoS protection against forged parameters:** before running Argon2id,
the implementation validates that the declared KDF parameters are within
safe bounds (`t_cost ≤ 64`, `m_cost ≤ 4 GiB`, `p_cost ≤ 16`). A tampered
file with absurd parameters (e.g. t=1000, m=10 GiB) is rejected
immediately without invoking Argon2id.

**Post-quantum resistance:** HMAC-SHA256 provides 128 bits of
post-quantum security (Grover on SHA-256 → 2¹²⁸ operations), which is sufficient.

---

## 3. BLAKE3

**Role:** internal sub-key derivation, nonce derivation, and
Merkle tree computation.

**Standard:** BLAKE3 (2020), successor to BLAKE2. Implemented via the
Rust `blake3` crate.

**Two interfaces used:**

### 3a. `blake3::keyed_hash(key, data) → [u8; 32]`

BLAKE3 hash with a 32-byte key. Used for block key derivation:

```
block_key_i = blake3::keyed_hash(DEK, i.to_le_bytes())
```

The key (`DEK`) ensures outputs are pseudo-random even if
the input (`i`) is predictable. Each block `i` gets a unique,
independent key.

### 3b. `blake3::derive_key(context_string, material) → [u8; 32]`

Fixed-context key derivation (KDF). The context is a unique ASCII
string that separates cryptographic domains,
preventing reuse of an output in a different role.

Uses in Arsenic:

| Context string | Input | Output |
|---|---|---|
| `"Arsenic V1 Block Nonce"` | `file_base_nonce \|\| i.to_le_bytes()` | `block_nonce_i[24]` |
| `"Arsenic V1 Metadata Key"` | `DEK[32]` | `MetaKey[32]` |
| `"Arsenic V1 Meta Nonce"` | `DEK[32]` | `MetaNonce[12]` |
| `"Arsenic V1 Merkle Leaf v1"` | encrypted block | `leaf_i[32]` |
| `"Arsenic V1 Merkle Node v1"` | `left[32] \|\| right[32]` | `node[32]` |
| `"Arsenic V1 KEK Nonce XChaCha20"` | `kek_nonce[12] \|\| 0×20` | extended nonce [24] |
| `"Arsenic V1 KEK Nonce DeoxysII256"` | `kek_nonce[12] \|\| 0×20` | extended nonce [15] |
| `"Arsenic V2 X25519 Wrapping Key"` | `shared_secret_x25519[32]` | `wrapping_key[32]` |
| `"Arsenic Hybrid KEM"` | see §5 | `wrapping_key[32]` |
| `"Arsenic ML-KEM d"` | `x25519_sk[32]` | `d[32]` (ML-KEM seed) |
| `"Arsenic ML-KEM z"` | `x25519_sk[32]` | `z[32]` (ML-KEM seed) |

**Why BLAKE3 rather than HKDF-SHA256 or SHA3-KDF?**
- Speed: BLAKE3 is ~3–5× faster than SHA-256 on modern CPUs,
  thanks to internal parallelism and SIMD optimisations (AVX2, NEON)
- Proven security: built on a permutation-based structure
  (ChaCha-like), different from the Merkle-Damgård family
- Native derivation API: `derive_key` directly integrates domain
  separation without HKDF boilerplate

**Post-quantum resistance:** BLAKE3 is a symmetric hash function.
Grover reduces security from 256 bits to 128 effective bits —
sufficient for long-term post-quantum resistance.

---

## 4. AEAD Ciphers

All AEAD ciphers used produce a **16-byte authentication tag**
(`GCM_TAG = 16`). The user can independently choose the cipher
for the header (keys, metadata) and the payload (data blocks).

### 4a. Deoxys-II-256

**Standard:** submission to the CAESAR competition 2013–2019, finalist in the
"defence-in-depth" category. Based on AES permutations in tweakable
block cipher (TBC) mode.

**Characteristics:**

| Property | Value |
|---|---|
| Type | Tweakable block cipher AEAD (TBAR) |
| Key size | 256 bits |
| Native nonce | 120 bits (15 bytes) |
| Tag | 128 bits (16 bytes) |
| Security | ≥ 128 bits classical |
| Hardware acceleration | Yes (AES-NI) |

**Default role:** header encryption (WrappedDEK, ProtectedMetadata,
hybrid keyslots).

**Why Deoxys-II-256 for the header?**
- TBC mode offers "beyond-birthday-bound" security: security is
  maintained even after 2⁹⁶ calls (unlike classical AES-GCM which
  degrades at 2⁶⁴ blocks)
- AES-based, accelerated by AES-NI on x86/ARM
- Resistant to nonce-reuse attacks for keyslots (which use
  randomly generated nonces)

**Nonce handling for envelope:**
The 12-byte `kek_nonce` stored in the header is extended to 15 bytes via
`BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce || 0×20)`.

For payload blocks, the 24-byte `block_nonce_i` is truncated to 15:
`block_nonce_i[0..15]`.

---

### 4b. XChaCha20-Poly1305

**Standard:** RFC 8439 (ChaCha20-Poly1305), XChaCha20 extension with 192-bit
nonce (IETF draft).

**Characteristics:**

| Property | Value |
|---|---|
| Type | Stream cipher + MAC (ARX) |
| Key size | 256 bits |
| Native nonce | 192 bits (24 bytes) |
| Tag | 128 bits (16 bytes) |
| Security | ≥ 128 bits classical |
| Hardware acceleration | No (but fast in pure software) |

**Default role:** payload encryption (data blocks).

**Why XChaCha20 for the payload?**
- The "X" extension extends the nonce from 96 to 192 bits, practically
  eliminating nonce collision risk on large files processed in parallel
- Very fast pure-software implementation on CPUs without AES-NI
  (embedded, mobile)
- Based on ChaCha20, built on ARX (Addition, Rotation,
  XOR) operations — structurally different from AES, offering
  algorithmic diversity
- Poly1305 is a one-time MAC: even if a nonce is reused, only
  the authenticity bit is compromised, not confidentiality

**Nonce handling for envelope:**
The 12-byte `kek_nonce` is extended to 24 via
`BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20", kek_nonce || 0×20)`.

For blocks, `block_nonce_i[0..24]` is used directly (24 bytes).

---

### 4c. AES-256-GCM-SIV

**Standard:** RFC 8452, designed by Google and Shay Gueron.

**Characteristics:**

| Property | Value |
|---|---|
| Type | Synthetic IV AEAD (SIV) |
| Key size | 256 bits |
| Native nonce | 96 bits (12 bytes) |
| Tag | 128 bits (16 bytes) |
| Security | ≥ 128 bits classical |
| Nonce-misuse resistance | Yes |
| Hardware acceleration | Yes (AES-NI + CLMUL) |

**Key feature:** AES-GCM-SIV is **nonce-misuse resistant**. If the
same nonce is used twice with the same key, confidentiality
is preserved (only authenticity may be compromised). Standard AES-GCM
fails catastrophically on nonce reuse.

**Nonce handling:**
The 12-byte `kek_nonce` is used directly for keyslots and
metadata. For blocks, `block_nonce_i[0..12]` is used.

---

## 5. Post-quantum Hybrid KEM

Asymmetric encryption in Arsenic uses a **hybrid KEM** combining
X25519 (classical) and ML-KEM-768 (post-quantum). Hybridisation guarantees
that security is maintained as long as **at least one** of the two components
is not compromised.

### 5a. X25519 (ECDH)

**Standard:** RFC 7748, based on Daniel J. Bernstein's Curve25519.

**Characteristics:**

| Property | Value |
|---|---|
| Type | Elliptic-curve Diffie-Hellman key exchange |
| Curve | Curve25519 (Montgomery) |
| Key size | 32 bytes (private and public) |
| Shared secret | 32 bytes |
| Classical security | ~128 bits (255-bit curve) |
| Post-quantum security | ✗ (Shor breaks ECDH in O(n³)) |

**Use in Arsenic:**
Each keyslot generates a single-use **ephemeral** X25519 keypair:

```
eph_sk ← random[32]
eph_pk ← X25519(eph_sk, G)   (scalar multiplication on Curve25519)
ss_x25519 ← X25519(eph_sk, recipient_pk_x25519)
```

The ephemeral key guarantees **forward secrecy**: even if the recipient's
private key is compromised later, past messages remain
confidential because `eph_sk` is never stored.

**Why Curve25519?**
- Resistant to side-channel attacks by construction (constant-time
  arithmetic on correct implementations)
- No potentially backdoored parameters (unlike
  NIST curves P-256/P-384 whose constants have obscure origins)
- Widely adopted (SSH, TLS 1.3, Signal, WireGuard)

---

### 5b. ML-KEM-768 (CRYSTALS-Kyber)

**Standard:** NIST FIPS 203 (August 2024) — the first post-quantum
KEM algorithm standardised by NIST.

**Characteristics:**

| Property | Value |
|---|---|
| Type | Key Encapsulation Mechanism (KEM) over module lattices |
| Security level | NIST level 3 (≈ AES-192) |
| Encapsulation key (public) | 1 184 bytes |
| Decapsulation key (secret) | 2 400 bytes (seed: 64 bytes) |
| Ciphertext | 1 088 bytes |
| Shared secret | 32 bytes |
| Security assumption | Module-LWE (Module Learning With Errors) |
| Post-quantum security | ✓ (Shor does not apply to lattices) |

**Difference from X25519 — KEM API vs. Key Agreement:**

```
X25519 (ECDH):
  Alice: (eph_sk, eph_pk) ← KeyGen()
  Alice → Bob: eph_pk
  Bob:   ss ← ECDH(bob_sk, eph_pk)
  Alice: ss ← ECDH(eph_sk, bob_pk)
  → identical ss on both sides

ML-KEM-768 (KEM):
  Bob has: (dk, ek) ← KeyGen()
  Alice: (ct, ss) ← Encaps(ek)   ← only Alice knows ss before sending
  Alice → Bob: ct
  Bob:   ss ← Decaps(dk, ct)
  → identical ss on both sides
```

**Deterministic derivation from X25519 key:**
To simplify key management, the ML-KEM seed is derived from the
X25519 private key, avoiding storing a second secret:

```
seed[64] = BLAKE3_derive_key("Arsenic ML-KEM d", x25519_sk)[32]
         || BLAKE3_derive_key("Arsenic ML-KEM z", x25519_sk)[32]

(dk_mlkem, ek_mlkem) ← ML-KEM-768.KeyGen_internal(d=seed[0..32], z=seed[32..64])
```

A single 32-byte `.key` file is sufficient to manage the entire
hybrid keypair.

**Deterministic encapsulation:**
To avoid any dependency on a specific version of the random number generator
(`rand_core`), Arsenic uses
`encapsulate_deterministic(m)` with `m ← rand::random::<[u8; 32]>()`.
Randomisation is provided by the caller.

---

### Hybrid Construction and Binding

The keyslot wrapping key combines both shared secrets to prevent
any substitution or component isolation attack:

```
wrapping_key = BLAKE3_derive_key(
    "Arsenic Hybrid KEM",
    eph_x25519_pk[32]     ← public, binds the ephemeral X25519 key
    || mlkem_ct[1088]     ← public, binds the ML-KEM ciphertext
    || ss_x25519[32]      ← secret X25519
    || ss_mlkem[32]       ← secret ML-KEM
)
```

This construction guarantees:
1. **Bind-and-commit**: `wrapping_key` is cryptographically bound to
   all public AND secret elements, making any "key commitment"
   attack impossible
2. **Domain separation**: the string `"Arsenic Hybrid KEM"` prevents
   reuse of this output for another purpose
3. **Defence in depth**: if X25519 is broken (quantum computer),
   ML-KEM maintains security. If ML-KEM is vulnerable (algorithmic flaw),
   X25519 maintains classical security

---

## 6. Merkle Tree

**Role:** verify the integrity of the entire encrypted file **before**
writing a single byte of plaintext.

**Construction:** domain-separated BLAKE3 binary tree, computed over
**encrypted blocks** (not plaintext).

```
leaf_i  = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1",  encrypted_block_i)
node(l, r) = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", l[32] || r[32])
```

Nodes are computed bottom-up in successive pairs. If the number
of nodes is odd, the last one is promoted as-is (no duplication). The
root is stored in the encrypted `ProtectedMetadata` (TLV tag `0x02`).

**Why BLAKE3 and not SHA-256 for Merkle?**
- BLAKE3 is ~5× faster than SHA-256 for block hashing
- `derive_key` with distinct contexts for leaves and nodes
  eliminates **second preimage confusion attacks** (a leaf
  cannot be confused with an internal node)
- A naive SHA-256 tree without domain separation is vulnerable to
  this class of attack

**Security properties:**
- Authenticates each block **and** their order (the index is bound as AAD in
  each block AEAD)
- Prevents silent truncation (the number of blocks is implicit in
  the root)
- Computed over ciphertext → verification without decryption in pass 1

---

## 7. Bech32

**Role:** human-readable encoding of public and private keys.

**Standard:** adapted from BIP-0173 (Bitcoin), using the
`qpzry9x8gf2tvdw0s3jn54khce6mua7l` alphabet (32 characters, 5 bits/char).

Arsenic uses Bech32 **without checksum** (keys are verified
cryptographically on use, not at encoding time).

| Type | Prefix | Length | Example |
|---|---|---|---|
| X25519 public key | `arsenic1` | 60 chars | `arsenic1ql3z7hjy…` |
| Private key | `ARSENIC-SECRET-KEY-1` | 72 chars | `ARSENIC-SECRET-KEY-1GQ9…` |
| ML-KEM-768 encapsulation key | `arsenic1m` | ~1 955 chars | `arsenic1mq…` |

**Calculation:**
32 bytes × 8 bits = 256 bits → ⌈256/5⌉ = 52 bech32 chars + prefix.
For ML-KEM: 1 184 bytes × 8 bits = 9 472 bits → 1 946 characters.

**Why Bech32 rather than Base64/Hex?**
- The alphabet avoids ambiguous characters (O/0, I/l/1)
- Entirely lowercase for X25519 (easy to copy without case errors)
- The UPPERCASE convention for private keys visually signals danger

---

## 8. Zeroize

**Role:** securely erase sensitive values from memory
when they are no longer needed.

**Standard:** Rust `zeroize` crate, conforming to
security memory recommendations (CERT C, MISRA, NIST).

**Problem solved:** the C/Rust compiler may optimise and remove
`memset(secret, 0, len)` if it detects the memory is no longer used
afterward. `Zeroize` uses memory barriers and volatile writes
to guarantee effective erasure.

**Use in Arsenic:**
The `Secret<T>` type is a wrapper around any sensitive value:

```rust
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();  // zeroes on destruction
    }
}
```

Values covered:
- Password (`Secret<String>`)
- DEK — Data Encryption Key (`[u8; 32]` + explicit `zeroize()`)
- KEK — Key Encryption Key (`Secret<[u8; 32]>`)
- Intermediate `dek_vec` during envelope decryption
- Private key vectors in derivation functions

**Note:** the ML-KEM decapsulation key (2 400 bytes) is computed
in RAM on demand and never stored outside the stack frame of the
function that creates it. The `ml-kem` crate uses the `zeroize` feature to
automatically erase internal structures.

---

## 9. Overview

```
Password ──► Argon2id ──► KEK[32] ──► AEAD ──► WrappedDEK[48]
                                                      │
                  ┌───────────────────────────────────┘
                  ▼
               DEK[32] (random per file)
                  │
                  ├──► BLAKE3_keyed_hash ──► block_key_i[32] ──► AEAD ──► encrypted_block_i
                  ├──► BLAKE3_derive_key ──► block_nonce_i[24]
                  ├──► BLAKE3_derive_key ──► MetaKey/MetaNonce ──► AEAD ──► ProtectedMetadata
                  │
                  └──► (for each recipient)
                         X25519_ECDH ──┐
                         ML-KEM-768 ──┼──► BLAKE3 "Arsenic Hybrid KEM" ──► wrapping_key
                                      └──► AEAD ──► wrapped_dek in HybridKeyslot

┌──────────────────────────────────────────────────────────┐
│ BLAKE3 Merkle tree  (over all encrypted blocks)           │
│   leaf_i = BLAKE3_derive_key("…Leaf…", encrypted_block_i) │
│   root   → stored in ProtectedMetadata (decrypted)        │
│   Full verification before any plaintext write             │
└──────────────────────────────────────────────────────────┘

Header protected by: HMAC-SHA256(Argon2id(password), public_header)
```

### Post-quantum Resistance Summary

| Component | Algorithm | PQ-safe? | Reason |
|---|---|---|---|
| Payload encryption | XChaCha20 / Deoxys-II / AES-GCM-SIV | ✓ | Symmetric 256 bits, Grover → 128 bits |
| Password KDF | Argon2id | ✓ | Symmetric, Grover → 128 bits |
| Header MAC | HMAC-SHA256 | ✓ | 128 bits post-quantum |
| Internal derivation | BLAKE3 | ✓ | Symmetric |
| X25519 keyslot | X25519 | ✗ | Shor breaks ECDH |
| ML-KEM-768 keyslot | ML-KEM-768 | ✓ | FIPS 203, resists Shor |
| **Hybrid keyslot** | **X25519 + ML-KEM-768** | **✓** | Secure if either holds |

The only classically vulnerable component is X25519, and it is **always
paired with ML-KEM-768** in the hybrid keyslot. If a sufficiently powerful
quantum computer were to exist, it would break X25519 but
not ML-KEM-768, leaving the DEK (and thus the data) protected.
