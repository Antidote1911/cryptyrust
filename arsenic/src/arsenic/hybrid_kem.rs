//! ML-KEM-768 helpers with plain byte-array I/O.
//!
//! All functions accept and return fixed-size `[u8; N]` arrays so the rest of
//! the codebase never needs to import ml-kem types directly.
//!
//! ## Key derivation
//!
//! Both the ML-KEM decapsulation and encapsulation keys are derived
//! **deterministically** from the 32-byte X25519 private key that the user
//! already stores in their `.key` file.  No extra secret material needs to be
//! stored.

use ml_kem::{
    B32, MlKem768, Seed,
    kem::{Ciphertext, Decapsulate, Key, KeyExport},
    DecapsulationKey768, EncapsulationKey768,
};

/// Byte length of an ML-KEM-768 encapsulation (public) key.
pub const EK_LEN: usize = 1184;
/// Byte length of an ML-KEM-768 ciphertext.
pub const CT_LEN: usize = 1088;

// ── Seed derivation ───────────────────────────────────────────────────────────

fn seed_from_x25519(sk: &[u8; 32]) -> [u8; 64] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&blake3::derive_key("Arsenic ML-KEM d", sk));
    seed[32..].copy_from_slice(&blake3::derive_key("Arsenic ML-KEM z", sk));
    seed
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Derive the ML-KEM-768 encapsulation key from an X25519 private key.
pub fn encapsulation_key(x25519_sk: &[u8; 32]) -> [u8; EK_LEN] {
    let seed: Seed = seed_from_x25519(x25519_sk).as_slice().try_into().unwrap();
    let dk = DecapsulationKey768::from_seed(seed);
    let ek_key: Key<EncapsulationKey768> = dk.encapsulation_key().to_bytes();
    let mut out = [0u8; EK_LEN];
    out.copy_from_slice(ek_key.as_slice());
    out
}

/// Encapsulate: produce a ciphertext and shared secret for the given public key.
///
/// `m` is 32 bytes of fresh randomness from the OS CSPRNG — caller provides it.
/// Using caller-supplied randomness avoids any `rand_core` version coupling.
pub fn encaps(ek_bytes: &[u8; EK_LEN], m: &[u8; 32]) -> ([u8; CT_LEN], [u8; 32]) {
    let ek_key: Key<EncapsulationKey768> = ek_bytes.as_slice().try_into().unwrap();
    let ek = EncapsulationKey768::new(&ek_key).expect("valid ML-KEM-768 public key");
    let m_arr: B32 = m.as_slice().try_into().unwrap();
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ct_out = [0u8; CT_LEN];
    ct_out.copy_from_slice(ct.as_slice());
    let mut ss_out = [0u8; 32];
    ss_out.copy_from_slice(ss.as_slice());
    (ct_out, ss_out)
}

/// Decapsulate: recover the shared secret from a ciphertext and X25519 private key.
pub fn decaps(x25519_sk: &[u8; 32], ct_bytes: &[u8; CT_LEN]) -> [u8; 32] {
    let seed: Seed = seed_from_x25519(x25519_sk).as_slice().try_into().unwrap();
    let dk = DecapsulationKey768::from_seed(seed);
    let ct: Ciphertext<MlKem768> = ct_bytes.as_slice().try_into().unwrap();
    let ss = dk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    out
}
