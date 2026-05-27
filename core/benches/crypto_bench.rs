// Throughput benchmarks for all encryption modes.
//
// Benchmark groups:
//   v1_encrypt / v1_decrypt   — V1 streaming AEAD (XChaCha20, AES-GCM, AES-GCM-SIV)
//                               Uses Interactive KDF (Argon2id, 10 MB, 4 iters).
//                               KDF cost is included — this reflects real-world latency.
//
//   v2_encrypt / v2_decrypt   — Arsenic V2 (XChaCha20 blocks + Serpent-GCM header).
//                               Two sub-groups:
//                                 "cipher"  — minimal KDF (t=1, m=64 KB, p=1) isolates
//                                             pure cipher throughput.
//                                 "kdf"     — Interactive KDF (256 MB) reflects production cost.
//
//   kdf_cost                  — KDF-only cost on a trivially small file (no cipher overhead).

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use cryptyrust_core::{
    Algorithm, BenchMode, DeriveStrength, HashMode, Secret, Ui,
    arsenic::{self, ArsenicParams, ArsenicStrength},
    decrypt, encrypt,
};
use std::io::Cursor;

struct NoUi;
impl Ui for NoUi {
    fn output(&self, _: i32) {}
}

fn pw() -> Secret<String> {
    Secret::new("bench_password".into())
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

// Bench sizes: 64 KB, 1 MB, 16 MB
const SIZES_KB: &[usize] = &[64, 1024, 16 * 1024];

// ── V1 helpers ────────────────────────────────────────────────────────────────

fn v1_encrypt(data: &[u8], algo: Algorithm) -> Vec<u8> {
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::with_capacity(data.len() + 256));
    encrypt(
        &mut input, &mut output, &pw(), &NoUi,
        data.len() as u64, algo, DeriveStrength::Interactive,
        HashMode::NoHash, BenchMode::WriteToFilesystem,
    )
    .unwrap();
    output.into_inner()
}

fn v1_decrypt(ct: &[u8]) {
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::with_capacity(ct.len()));
    decrypt(
        &mut input, &mut output, &pw(), &NoUi,
        ct.len() as u64, HashMode::NoHash, BenchMode::WriteToFilesystem,
    )
    .unwrap();
}

// ── V2 helpers ────────────────────────────────────────────────────────────────

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

// ── V1 encrypt ────────────────────────────────────────────────────────────────

fn bench_v1_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("v1_encrypt");
    group.sample_size(10);

    let algos = [
        ("XChaCha20Poly1305", Algorithm::XChaCha20Poly1305),
        ("AES-256-GCM", Algorithm::Aes256Gcm),
        ("AES-256-GCM-SIV", Algorithm::Aes256GcmSiv),
    ];

    for &size_kb in SIZES_KB {
        let size = size_kb * 1024;
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        for (name, algo) in algos {
            group.bench_with_input(
                BenchmarkId::new(name, format!("{size_kb} KB")),
                &data,
                |b, data| b.iter(|| v1_encrypt(data, algo)),
            );
        }
    }
    group.finish();
}

// ── V1 decrypt ────────────────────────────────────────────────────────────────

fn bench_v1_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("v1_decrypt");
    group.sample_size(10);

    let algos = [
        ("XChaCha20Poly1305", Algorithm::XChaCha20Poly1305),
        ("AES-256-GCM", Algorithm::Aes256Gcm),
        ("AES-256-GCM-SIV", Algorithm::Aes256GcmSiv),
    ];

    for &size_kb in SIZES_KB {
        let size = size_kb * 1024;
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        for (name, algo) in algos {
            let ct = v1_encrypt(&data, algo);
            group.bench_with_input(
                BenchmarkId::new(name, format!("{size_kb} KB")),
                &ct,
                |b, ct| b.iter(|| v1_decrypt(ct)),
            );
        }
    }
    group.finish();
}

// ── V2 encrypt — cipher throughput (minimal KDF) ──────────────────────────────

fn bench_v2_encrypt_cipher(c: &mut Criterion) {
    let params = ArsenicParams { t_cost: 1, m_cost: 64, p_cost: 1 };
    let mut group = c.benchmark_group("v2_encrypt_cipher");
    group.sample_size(20);

    for &size_kb in SIZES_KB {
        let size = size_kb * 1024;
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("Arsenic", format!("{size_kb} KB")),
            &data,
            |b, data| b.iter(|| v2_encrypt(data, &params)),
        );
    }
    group.finish();
}

// ── V2 decrypt — cipher throughput (minimal KDF) ──────────────────────────────

fn bench_v2_decrypt_cipher(c: &mut Criterion) {
    let params = ArsenicParams { t_cost: 1, m_cost: 64, p_cost: 1 };
    let mut group = c.benchmark_group("v2_decrypt_cipher");
    group.sample_size(20);

    for &size_kb in SIZES_KB {
        let size = size_kb * 1024;
        let data = payload(size);
        let ct = v2_encrypt(&data, &params);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("Arsenic", format!("{size_kb} KB")),
            &ct,
            |b, ct| b.iter(|| v2_decrypt(ct)),
        );
    }
    group.finish();
}

// ── KDF cost isolation ────────────────────────────────────────────────────────
//
// Tiny payload (1 byte) so cipher time is negligible.
// Shows the raw cost of each Argon2id configuration.

fn bench_kdf_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_cost");
    group.sample_size(10);

    // V1 Interactive: 10 MB, 4 iterations
    group.bench_function("v1_interactive", |b| {
        b.iter(|| v1_encrypt(b"x", Algorithm::XChaCha20Poly1305));
    });

    // V2 Interactive: 256 MB, 4 iterations (via ArsenicStrength)
    let v2_interactive = ArsenicParams::from(ArsenicStrength::Interactive);
    group.bench_function("v2_interactive_256mb", |b| {
        b.iter(|| v2_encrypt(b"x", &v2_interactive));
    });

    // V2 minimal: 64 KB, 1 iteration (baseline — effectively no KDF cost)
    let v2_minimal = ArsenicParams { t_cost: 1, m_cost: 64, p_cost: 1 };
    group.bench_function("v2_minimal_kdf", |b| {
        b.iter(|| v2_encrypt(b"x", &v2_minimal));
    });

    group.finish();
}

// ── Cipher-only throughput comparison at 16 MB ────────────────────────────────
//
// All modes with minimal KDF so the comparison is purely about cipher speed.
// V1 doesn't expose custom KDF params — its Interactive (10 MB) is already
// included here; for a fair cipher-only comparison use the "v2_encrypt_cipher"
// group and note V1 KDF adds ~X ms overhead.

fn bench_throughput_comparison(c: &mut Criterion) {
    let size = 16 * 1024 * 1024; // 16 MB
    let data = payload(size);
    let v2_minimal = ArsenicParams { t_cost: 1, m_cost: 64, p_cost: 1 };

    let mut group = c.benchmark_group("throughput_16mb_encrypt");
    group.throughput(Throughput::Bytes(size as u64));
    group.sample_size(10);

    group.bench_function("XChaCha20Poly1305 (V1)", |b| {
        b.iter(|| v1_encrypt(&data, Algorithm::XChaCha20Poly1305));
    });
    group.bench_function("AES-256-GCM (V1)", |b| {
        b.iter(|| v1_encrypt(&data, Algorithm::Aes256Gcm));
    });
    group.bench_function("AES-256-GCM-SIV (V1)", |b| {
        b.iter(|| v1_encrypt(&data, Algorithm::Aes256GcmSiv));
    });
    group.bench_function("Arsenic V2 (minimal KDF)", |b| {
        b.iter(|| v2_encrypt(&data, &v2_minimal));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_v1_encrypt,
    bench_v1_decrypt,
    bench_v2_encrypt_cipher,
    bench_v2_decrypt_cipher,
    bench_kdf_cost,
    bench_throughput_comparison,
);
criterion_main!(benches);
