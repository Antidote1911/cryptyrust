//! ML-KEM helpers (768 and 1024) with plain byte-array I/O.
//!
//! All public functions accept/return fixed-size `[u8; N]` arrays so the rest
//! of the codebase never needs to import ml-kem types directly.
//!
//! ## Key material
//!
//! Each keypair is derived from a **64-byte ML-KEM seed** (`d[32] || z[32]`).
//! For independently-seeded keys, the caller generates this seed from the OS
//! CSPRNG independently of the X25519 private key.  For compatibility with
//! legacy key files that only stored a 32-byte X25519 seed, `seed_from_x25519`
//! is kept as a migration helper.

use ml_kem::{
    B32, MlKem768, MlKem1024, Seed,
    kem::{Ciphertext, Decapsulate, Key, KeyExport},
    DecapsulationKey768, EncapsulationKey768,
    DecapsulationKey1024, EncapsulationKey1024,
};

// ── ML-KEM-768 ────────────────────────────────────────────────────────────────

/// Byte length of an ML-KEM-768 encapsulation (public) key.
pub const EK_LEN_768: usize = 1184;
/// Byte length of an ML-KEM-768 ciphertext.
pub const CT_LEN_768: usize = 1088;

/// Backward-compat alias for ML-KEM-768 encapsulation key length.
pub const EK_LEN: usize = EK_LEN_768;

// ── ML-KEM-1024 ───────────────────────────────────────────────────────────────

/// Byte length of an ML-KEM-1024 encapsulation (public) key.
pub const EK_LEN_1024: usize = 1568;
/// Byte length of an ML-KEM-1024 ciphertext.
pub const CT_LEN_1024: usize = 1568;

// ── Legacy helper (backward compat for 32-byte key files) ────────────────────

/// Derive a 64-byte ML-KEM seed from a 32-byte X25519 private key via BLAKE3.
///
/// Used only when reading old key files that predate independent seed storage.
/// New key files store the ML-KEM seed independently (64 bytes of OS entropy).
pub fn seed_from_x25519(sk: &[u8; 32]) -> [u8; 64] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&blake3::derive_key("Arsenic ML-KEM d", sk));
    seed[32..].copy_from_slice(&blake3::derive_key("Arsenic ML-KEM z", sk));
    seed
}

// ── ML-KEM-768 public API ─────────────────────────────────────────────────────

/// Derive the ML-KEM-768 encapsulation key from a 64-byte seed (`d[32] || z[32]`).
pub fn encapsulation_key_768(mlkem_seed: &[u8; 64]) -> [u8; EK_LEN_768] {
    let seed: Seed = mlkem_seed.as_slice().try_into().expect("64 bytes");
    let dk = DecapsulationKey768::from_seed(seed);
    let ek: Key<EncapsulationKey768> = dk.encapsulation_key().to_bytes();
    let mut out = [0u8; EK_LEN_768];
    out.copy_from_slice(ek.as_slice());
    out
}

/// Encapsulate for ML-KEM-768: produce `(ciphertext[1088], shared_secret[32])`.
///
/// `m` must be 32 bytes of fresh OS CSPRNG randomness.
pub fn encaps_768(ek_bytes: &[u8; EK_LEN_768], m: &[u8; 32]) -> ([u8; CT_LEN_768], [u8; 32]) {
    let ek_key: Key<EncapsulationKey768> = ek_bytes.as_slice().try_into().expect("EK_LEN_768");
    let ek = EncapsulationKey768::new(&ek_key).expect("valid ML-KEM-768 public key");
    let m_arr: B32 = m.as_slice().try_into().unwrap();
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ct_out = [0u8; CT_LEN_768];
    ct_out.copy_from_slice(ct.as_slice());
    let mut ss_out = [0u8; 32];
    ss_out.copy_from_slice(ss.as_slice());
    (ct_out, ss_out)
}

/// Decapsulate ML-KEM-768: recover the shared secret.
///
/// `mlkem_seed` is the 64-byte seed (`d[32] || z[32]`) for the recipient.
pub fn decaps_768(mlkem_seed: &[u8; 64], ct_bytes: &[u8; CT_LEN_768]) -> [u8; 32] {
    let seed: Seed = mlkem_seed.as_slice().try_into().expect("64 bytes");
    let dk = DecapsulationKey768::from_seed(seed);
    let ct: Ciphertext<MlKem768> = ct_bytes.as_slice().try_into().expect("CT_LEN_768");
    let ss = dk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    out
}


// ── ML-KEM-1024 public API ────────────────────────────────────────────────────

/// Derive the ML-KEM-1024 encapsulation key from a 64-byte seed.
pub fn encapsulation_key_1024(mlkem_seed: &[u8; 64]) -> [u8; EK_LEN_1024] {
    let seed: Seed = mlkem_seed.as_slice().try_into().expect("64 bytes");
    let dk = DecapsulationKey1024::from_seed(seed);
    let ek: Key<EncapsulationKey1024> = dk.encapsulation_key().to_bytes();
    let mut out = [0u8; EK_LEN_1024];
    out.copy_from_slice(ek.as_slice());
    out
}

/// Encapsulate for ML-KEM-1024: produce `(ciphertext[1568], shared_secret[32])`.
pub fn encaps_1024(ek_bytes: &[u8; EK_LEN_1024], m: &[u8; 32]) -> ([u8; CT_LEN_1024], [u8; 32]) {
    let ek_key: Key<EncapsulationKey1024> = ek_bytes.as_slice().try_into().expect("EK_LEN_1024");
    let ek = EncapsulationKey1024::new(&ek_key).expect("valid ML-KEM-1024 public key");
    let m_arr: B32 = m.as_slice().try_into().unwrap();
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ct_out = [0u8; CT_LEN_1024];
    ct_out.copy_from_slice(ct.as_slice());
    let mut ss_out = [0u8; 32];
    ss_out.copy_from_slice(ss.as_slice());
    (ct_out, ss_out)
}

/// Decapsulate ML-KEM-1024.
pub fn decaps_1024(mlkem_seed: &[u8; 64], ct_bytes: &[u8; CT_LEN_1024]) -> [u8; 32] {
    let seed: Seed = mlkem_seed.as_slice().try_into().expect("64 bytes");
    let dk = DecapsulationKey1024::from_seed(seed);
    let ct: Ciphertext<MlKem1024> = ct_bytes.as_slice().try_into().expect("CT_LEN_1024");
    let ss = dk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    out
}
