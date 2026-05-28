use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::random;

use super::cipher_dispatch;
use super::CipherId;
use crate::Ui;

const BENCH_CIPHERS: [CipherId; 3] = [
    CipherId::DeoxysII256,
    CipherId::XChaCha20Poly1305,
    CipherId::Aes256GcmSiv,
];

/// Per-cipher benchmark result.
#[derive(Debug, Clone)]
pub struct CipherBenchResult {
    pub cipher: CipherId,
    /// Throughput in MiB/s for encryption.
    pub encrypt_mibps: f64,
    /// Throughput in MiB/s for decryption.
    pub decrypt_mibps: f64,
}

impl CipherBenchResult {
    /// Harmonic mean of encrypt+decrypt throughput — used for ranking.
    pub fn score(&self) -> f64 {
        2.0 / (1.0 / self.encrypt_mibps + 1.0 / self.decrypt_mibps)
    }
}

/// Returns the recommended `(hdr_cipher, pld_cipher)` pair from sorted results:
/// both are set to the fastest cipher found.
pub fn best_combination(results: &[CipherBenchResult]) -> (CipherId, CipherId) {
    let best = results
        .first()
        .map(|r| r.cipher)
        .unwrap_or(CipherId::DeoxysII256);
    (best, best)
}

/// Benchmark the three AEAD ciphers on `payload_mib` MiB of synthetic data.
///
/// A single Interactive-mode Argon2id derivation provides realistic key
/// material (the KDF cost is identical for all ciphers; running it once keeps
/// the total benchmark time under three seconds on modern hardware).
///
/// Progress 0–100 is reported via `ui`. Results are sorted fastest-first.
pub fn bench_cipher_combinations(payload_mib: usize, ui: &dyn Ui) -> Vec<CipherBenchResult> {
    ui.output(0);

    // ── Interactive Argon2id key derivation (once for all cipher tests) ──
    let salt: [u8; 16] = random();
    let argon_params = Params::new(256 * 1024, 4, 4, Some(32)).expect("valid Argon2id params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(b"bench", &salt, &mut key)
        .expect("Argon2id key derivation failed");

    ui.output(10);

    // ── Cipher throughput tests ───────────────────────────────────────────
    let payload: Vec<u8> = (0..payload_mib * 1024 * 1024).map(|i| i as u8).collect();
    let nonce24: [u8; 24] = random();
    let aad = 0u64.to_le_bytes();
    let step = 90 / BENCH_CIPHERS.len();

    let mut results = Vec::with_capacity(BENCH_CIPHERS.len());

    for (i, &cipher) in BENCH_CIPHERS.iter().enumerate() {
        let t0 = Instant::now();
        let ct = cipher_dispatch::block_encrypt(cipher, &key, &nonce24, &aad, &payload)
            .expect("bench encrypt");
        let encrypt_mibps = payload_mib as f64 / t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let _ = cipher_dispatch::block_decrypt(cipher, &key, &nonce24, &aad, &ct)
            .expect("bench decrypt");
        let decrypt_mibps = payload_mib as f64 / t1.elapsed().as_secs_f64();

        results.push(CipherBenchResult {
            cipher,
            encrypt_mibps,
            decrypt_mibps,
        });
        ui.output((10 + (i + 1) * step) as i32);
    }

    results.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    ui.output(100);
    results
}
