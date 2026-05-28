// Throughput benchmarks for Arsenic V2 encryption.
//
// Benchmark groups:
//   encrypt_cipher / decrypt_cipher  — minimal KDF (t=1, m=64 KB, p=1) isolates
//                                      pure cipher throughput.
//   encrypt_kdf / decrypt_kdf        — Interactive KDF (256 MB) reflects production cost.
//   kdf_cost                         — KDF-only cost on a trivially small file.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cryptyrust_core::{
    arsenic::{self, ArsenicParams, ArsenicStrength},
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

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

// Bench sizes: 64 KB, 1 MB, 16 MB
const SIZES_KB: &[usize] = &[64, 1024, 16 * 1024];

fn v2_encrypt(data: &[u8], params: &ArsenicParams) -> Vec<u8> {
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::with_capacity(data.len() + 512));
    arsenic::encrypt_arsenic(
        &mut input,
        &mut output,
        &pw(),
        &NoUi,
        data.len() as u64,
        params,
    )
    .unwrap();
    output.into_inner()
}

fn v2_decrypt(ct: &[u8]) {
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::with_capacity(ct.len()));
    arsenic::decrypt_arsenic(&mut input, &mut output, &pw(), &NoUi, ct.len() as u64).unwrap();
}

// ── Encrypt — cipher throughput (minimal KDF) ─────────────────────────────────

fn bench_encrypt_cipher(c: &mut Criterion) {
    let params = ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
    };
    let mut group = c.benchmark_group("encrypt_cipher");
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

// ── Decrypt — cipher throughput (minimal KDF) ─────────────────────────────────

fn bench_decrypt_cipher(c: &mut Criterion) {
    let params = ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
    };
    let mut group = c.benchmark_group("decrypt_cipher");
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

fn bench_kdf_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_cost");
    group.sample_size(10);

    let interactive = ArsenicParams::from(ArsenicStrength::Interactive);
    group.bench_function("interactive_256mb", |b| {
        b.iter(|| v2_encrypt(b"x", &interactive));
    });

    let minimal = ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
    };
    group.bench_function("minimal_kdf", |b| {
        b.iter(|| v2_encrypt(b"x", &minimal));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_cipher,
    bench_decrypt_cipher,
    bench_kdf_cost,
);
criterion_main!(benches);
