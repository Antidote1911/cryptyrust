// Throughput benchmarks for Arsenic V2 encryption.
//
// Benchmark groups
// ─────────────────────────────────────────────────────────────────────────────
//   encrypt_payload  — minimal KDF (t=1, m=64 KB, p=1) isolates pure cipher
//                      throughput for each of the three payload algorithms:
//                      XChaCha20-Poly1305, AES-256-GCM-SIV, Serpent-256-GCM.
//
//   decrypt_payload  — same ciphers, same sizes, decryption direction.
//
//   kdf_cost         — KDF-only cost on a trivially small payload:
//                      Interactive (256 MB, 4 passes) vs minimal KDF.
// ─────────────────────────────────────────────────────────────────────────────
//
// Run with:   cargo bench
// Filter:     cargo bench -- encrypt_payload
// HTML report generated under target/criterion/

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cryptyrust_core::{
    arsenic::{self, ArsenicParams, ArsenicStrength, CipherId},
    Secret, Ui,
};
use std::io::Cursor;

struct NoUi;
impl Ui for NoUi {
    fn output(&self, _: i32) {}
}

fn pw() -> Secret<String> {
    Secret::new("bench_password".into())
}

fn payload_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

/// Build params with a minimal KDF so benchmarks measure cipher throughput only.
fn minimal(pld_cipher: CipherId) -> ArsenicParams {
    ArsenicParams {
        t_cost: 1,
        m_cost: 64, // 64 KB — negligible KDF cost
        p_cost: 1,
        hdr_cipher: CipherId::SerpentGcm,
        pld_cipher,
    }
}

fn v2_encrypt(data: &[u8], params: &ArsenicParams) -> Vec<u8> {
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::with_capacity(data.len() + 512));
    arsenic::encrypt_arsenic(&mut input, &mut output, &pw(), &NoUi, data.len() as u64, params)
        .unwrap();
    output.into_inner()
}

fn v2_decrypt(ct: &[u8]) {
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::with_capacity(ct.len()));
    arsenic::decrypt_arsenic(&mut input, &mut output, &pw(), &NoUi, ct.len() as u64).unwrap();
}

// ── Payload ciphers × data sizes (encrypt) ───────────────────────────────────

fn bench_encrypt_payload(c: &mut Criterion) {
    // 64 KB · 1 MB · 16 MB
    const SIZES_KB: &[usize] = &[64, 1024, 16 * 1024];

    let ciphers: &[(CipherId, &str)] = &[
        (CipherId::XChaCha20Poly1305, "XChaCha20"),
        (CipherId::Aes256GcmSiv, "AES-GCM-SIV"),
        (CipherId::SerpentGcm, "Serpent-GCM"),
    ];

    let mut group = c.benchmark_group("encrypt_payload");
    group.sample_size(20);

    for &(pld_cipher, cipher_name) in ciphers {
        let params = minimal(pld_cipher);
        for &size_kb in SIZES_KB {
            let size = size_kb * 1024;
            let data = payload_data(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(cipher_name, format!("{size_kb} KB")),
                &data,
                |b, data| b.iter(|| v2_encrypt(data, &params)),
            );
        }
    }
    group.finish();
}

// ── Payload ciphers × data sizes (decrypt) ───────────────────────────────────

fn bench_decrypt_payload(c: &mut Criterion) {
    const SIZES_KB: &[usize] = &[64, 1024, 16 * 1024];

    let ciphers: &[(CipherId, &str)] = &[
        (CipherId::XChaCha20Poly1305, "XChaCha20"),
        (CipherId::Aes256GcmSiv, "AES-GCM-SIV"),
        (CipherId::SerpentGcm, "Serpent-GCM"),
    ];

    let mut group = c.benchmark_group("decrypt_payload");
    group.sample_size(20);

    for &(pld_cipher, cipher_name) in ciphers {
        let params = minimal(pld_cipher);
        for &size_kb in SIZES_KB {
            let size = size_kb * 1024;
            let data = payload_data(size);
            // Pre-encrypt outside the timed loop
            let ct = v2_encrypt(&data, &params);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(cipher_name, format!("{size_kb} KB")),
                &ct,
                |b, ct| b.iter(|| v2_decrypt(ct)),
            );
        }
    }
    group.finish();
}

// ── KDF cost (cipher-independent) ────────────────────────────────────────────

fn bench_kdf_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_cost");
    group.sample_size(10);

    // Interactive preset: t=4, m=256 MB, p=4
    let interactive = ArsenicParams::from(ArsenicStrength::Interactive);
    group.bench_function("interactive_256mb", |b| {
        b.iter(|| v2_encrypt(b"x", &interactive));
    });

    // Minimal KDF: isolates everything except Argon2id
    let minimal_kdf = minimal(CipherId::XChaCha20Poly1305);
    group.bench_function("minimal_kdf", |b| {
        b.iter(|| v2_encrypt(b"x", &minimal_kdf));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_payload,
    bench_decrypt_payload,
    bench_kdf_cost,
);
criterion_main!(benches);
