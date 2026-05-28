//! C-compatible FFI wrapper around `arsenic`.
//!
//! # Building
//! ```sh
//! cargo build --release -p cryptyrust_ffi
//! # outputs: target/release/libcryptyrustffi.so  (Linux)
//! #          target/release/libcryptyrustffi.a
//! ```
//!
//! # Generating the C header
//! ```sh
//! cargo install cbindgen
//! cbindgen --config ffi/cbindgen.toml --crate cryptyrust_ffi --output cryptyrust.h
//! ```

use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::os::raw::{c_char, c_void};
use std::path::Path;

use arsenic::{
    ArsenicParams, ArsenicStrength, CipherId, Compression,
    arsenic_rekey, bench_cipher_combinations, is_arsenic_file,
    encrypt_arsenic, decrypt_arsenic,
    CoreErr, Secret, Ui, ZSTD_DEFAULT_LEVEL,
};

// ── Thread-local last error ───────────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> =
        std::cell::RefCell::new(None);
}

fn set_last_error(msg: impl std::fmt::Display) {
    let s = CString::new(msg.to_string())
        .unwrap_or_else(|_| CString::new("(error message contained a null byte)").expect("static"));
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(s));
}

/// Returns a pointer to the last error message (null-terminated, UTF-8).
///
/// The pointer is valid until the next `arsenic_*` call on this thread.
/// Returns null if no error has occurred on this thread yet.
#[no_mangle]
pub extern "C" fn arsenic_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr())
    })
}

// ── Error codes ───────────────────────────────────────────────────────────────

/// Operation succeeded.
pub const ARSENIC_OK: i32 = 0;
/// Wrong password, corrupted data, or AEAD authentication failure.
pub const ARSENIC_ERR_DECRYPT: i32 = -1;
/// I/O error (file not found, permission denied, etc.).
pub const ARSENIC_ERR_IO: i32 = -2;
/// Invalid parameter (unknown cipher ID, unknown strength value, etc.).
pub const ARSENIC_ERR_PARAMS: i32 = -3;
/// File does not carry the Arsenic V1 magic bytes or has a bad version.
pub const ARSENIC_ERR_BAD_MAGIC: i32 = -4;
/// A required pointer argument was null.
pub const ARSENIC_ERR_NULL_PTR: i32 = -5;
/// Unclassified error — call `arsenic_last_error()` for details.
pub const ARSENIC_ERR_UNKNOWN: i32 = -99;

fn core_err_code(e: &CoreErr) -> i32 {
    match e {
        CoreErr::DecryptionError | CoreErr::DecryptFail(_) => ARSENIC_ERR_DECRYPT,
        CoreErr::IOError(_) | CoreErr::ReadError { .. } => ARSENIC_ERR_IO,
        CoreErr::Argon2Params | CoreErr::Argon2Hash | CoreErr::CreateCipher => {
            ARSENIC_ERR_PARAMS
        }
        CoreErr::BadSignature | CoreErr::BadHeaderVersion => ARSENIC_ERR_BAD_MAGIC,
        _ => ARSENIC_ERR_UNKNOWN,
    }
}

// ── Output buffer ─────────────────────────────────────────────────────────────

/// Heap-allocated byte buffer returned by `arsenic_encrypt` / `arsenic_decrypt`.
///
/// **Must** be released with `arsenic_free_buffer` exactly once.
/// `ptr` is null and `len` is 0 when the associated call returned an error.
#[repr(C)]
pub struct ArsBuffer {
    /// Pointer to the data bytes (owned by Rust, do not free directly).
    pub ptr: *mut u8,
    /// Number of valid bytes starting at `ptr`.
    pub len: usize,
}

impl ArsBuffer {
    fn from_vec(v: Vec<u8>) -> Self {
        let b = v.into_boxed_slice();
        let len = b.len();
        let ptr = Box::into_raw(b).cast::<u8>();
        Self { ptr, len }
    }

    fn null() -> Self {
        Self { ptr: std::ptr::null_mut(), len: 0 }
    }
}

/// Free a buffer previously returned by `arsenic_encrypt` or `arsenic_decrypt`.
///
/// Passing a null pointer or a zeroed buffer is safe and has no effect.
/// Do **not** call this more than once on the same buffer.
///
/// # Safety
/// `buf` must be null or point to a valid `ArsBuffer` produced by this library.
#[no_mangle]
pub unsafe extern "C" fn arsenic_free_buffer(buf: *mut ArsBuffer) {
    if buf.is_null() {
        return;
    }
    let b = unsafe { &mut *buf };
    if !b.ptr.is_null() && b.len > 0 {
        let slice = unsafe { std::slice::from_raw_parts_mut(b.ptr, b.len) };
        drop(unsafe { Box::from_raw(slice as *mut [u8]) });
        b.ptr = std::ptr::null_mut();
        b.len = 0;
    }
}

// ── Parameters ────────────────────────────────────────────────────────────────

/// Encryption parameters.
///
/// **Cipher IDs** — same bytes as stored in the Arsenic V1 header:
/// - `0x02` Deoxys-II-256    (default header cipher)
/// - `0x03` XChaCha20-Poly1305 (default payload cipher)
/// - `0x04` AES-256-GCM-SIV
///
/// **`strength`** — Argon2id cost preset:
/// - `0` Interactive  (256 MiB, ~1–3 s)
/// - `1` Sensitive    (1 GiB,  ~10–30 s)
///
/// **`compress`** — payload compression:
/// - `0` disabled
/// - `1` zstd level 3 (per-block, before encryption)
#[repr(C)]
pub struct ArsParams {
    pub hdr_cipher: u8,
    pub pld_cipher: u8,
    pub strength: u8,
    pub compress: u8,
}

/// Returns default parameters:
/// Deoxys-II-256 header · XChaCha20-Poly1305 payload · Interactive · no compression.
#[no_mangle]
pub extern "C" fn arsenic_default_params() -> ArsParams {
    ArsParams { hdr_cipher: 0x02, pld_cipher: 0x03, strength: 0, compress: 0 }
}

fn to_core_params(p: &ArsParams) -> Result<ArsenicParams, i32> {
    let hdr = CipherId::from_byte(p.hdr_cipher).map_err(|_| ARSENIC_ERR_PARAMS)?;
    let pld = CipherId::from_byte(p.pld_cipher).map_err(|_| ARSENIC_ERR_PARAMS)?;
    let strength = match p.strength {
        0 => ArsenicStrength::Interactive,
        1 => ArsenicStrength::Sensitive,
        _ => return Err(ARSENIC_ERR_PARAMS),
    };
    let compression = match p.compress {
        0 => Compression::None,
        1 => Compression::Zstd(ZSTD_DEFAULT_LEVEL),
        _ => return Err(ARSENIC_ERR_PARAMS),
    };
    Ok(ArsenicParams { hdr_cipher: hdr, pld_cipher: pld, compression, ..ArsenicParams::from(strength) })
}

// ── Progress callback ─────────────────────────────────────────────────────────

/// Optional progress callback.  `percentage` is in the range 0–100.
/// `user_data` is the value passed alongside the callback to the FFI function.
/// Pass null to ignore progress.
pub type ArsProgressFn =
    Option<unsafe extern "C" fn(percentage: i32, user_data: *mut c_void)>;

struct FfiUi {
    cb: ArsProgressFn,
    user_data: *mut c_void,
}

// SAFETY: the pointer is valid for the duration of one synchronous FFI call;
// the caller guarantees this by keeping the pointed-to data alive.
unsafe impl Send for FfiUi {}
unsafe impl Sync for FfiUi {}

impl Ui for FfiUi {
    fn output(&self, pct: i32) {
        if let Some(f) = self.cb {
            unsafe { f(pct, self.user_data) };
        }
    }
}

struct NoUi;
impl Ui for NoUi {
    fn output(&self, _: i32) {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert a C string pointer to an owned `String`, or return an FFI error code.
unsafe fn cstr_to_string(ptr: *const c_char, field: &str) -> Result<String, i32> {
    if ptr.is_null() {
        set_last_error(format!("{field} is null"));
        return Err(ARSENIC_ERR_NULL_PTR);
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map(str::to_owned).map_err(|_| {
        set_last_error(format!("{field} is not valid UTF-8"));
        ARSENIC_ERR_PARAMS
    })
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

/// Encrypt a plaintext buffer in memory.
///
/// On success writes the ciphertext to `*out` (caller must free with
/// `arsenic_free_buffer`) and returns `ARSENIC_OK`.
/// On failure returns a negative error code; `*out` is zeroed;
/// call `arsenic_last_error()` for a human-readable description.
///
/// `progress_fn` / `user_data`: optional progress callback (pass null to ignore).
///
/// # Safety
/// - `plaintext` must point to at least `plaintext_len` readable bytes.
/// - `password` and `params` must be valid non-null pointers.
/// - `out` must be a valid non-null pointer to an `ArsBuffer` the caller owns.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    password: *const c_char,
    params: *const ArsParams,
    progress_fn: ArsProgressFn,
    user_data: *mut c_void,
    out: *mut ArsBuffer,
) -> i32 {
    if out.is_null() {
        set_last_error("out is null");
        return ARSENIC_ERR_NULL_PTR;
    }
    unsafe { *out = ArsBuffer::null() };

    if plaintext.is_null() || params.is_null() {
        set_last_error("null pointer argument");
        return ARSENIC_ERR_NULL_PTR;
    }

    let pwd = match unsafe { cstr_to_string(password, "password") } {
        Ok(s) => s,
        Err(code) => return code,
    };
    let core_params = match to_core_params(unsafe { &*params }) {
        Ok(p) => p,
        Err(code) => { set_last_error("invalid cipher ID or strength"); return code; }
    };

    let data = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::new());
    let ui = FfiUi { cb: progress_fn, user_data };

    match encrypt_arsenic(
        &mut input, &mut output,
        &Secret::new(pwd), &ui,
        plaintext_len as u64, &core_params,
    ) {
        Ok(()) => {
            unsafe { *out = ArsBuffer::from_vec(output.into_inner()) };
            ARSENIC_OK
        }
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt a ciphertext buffer in memory.
///
/// On success writes the plaintext to `*out` (caller must free with
/// `arsenic_free_buffer`) and returns `ARSENIC_OK`.
/// Cipher parameters are read from the file header — no `ArsParams` needed.
///
/// # Safety
/// - `ciphertext` must point to at least `ciphertext_len` readable bytes.
/// - `password` must be a valid non-null pointer to a null-terminated string.
/// - `out` must be a valid non-null pointer to an `ArsBuffer` the caller owns.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    password: *const c_char,
    progress_fn: ArsProgressFn,
    user_data: *mut c_void,
    out: *mut ArsBuffer,
) -> i32 {
    if out.is_null() {
        set_last_error("out is null");
        return ARSENIC_ERR_NULL_PTR;
    }
    unsafe { *out = ArsBuffer::null() };

    if ciphertext.is_null() {
        set_last_error("ciphertext is null");
        return ARSENIC_ERR_NULL_PTR;
    }

    let pwd = match unsafe { cstr_to_string(password, "password") } {
        Ok(s) => s,
        Err(code) => return code,
    };

    let data = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::new());
    let ui = FfiUi { cb: progress_fn, user_data };

    match decrypt_arsenic(
        &mut input, &mut output,
        &Secret::new(pwd), &ui,
        ciphertext_len as u64,
    ) {
        Ok(_meta) => {
            unsafe { *out = ArsBuffer::from_vec(output.into_inner()) };
            ARSENIC_OK
        }
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── Rekey file ────────────────────────────────────────────────────────────────

/// Change the password of an Arsenic V1 file in-place.
///
/// Returns `ARSENIC_OK` on success.
/// A crash-safe `.bak` backup is written before the in-place write and removed
/// on success (see FORMAT.md §7 for the full crash-recovery protocol).
///
/// # Safety
/// All pointer arguments must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn arsenic_rekey_file(
    path: *const c_char,
    old_password: *const c_char,
    new_password: *const c_char,
    progress_fn: ArsProgressFn,
    user_data: *mut c_void,
) -> i32 {
    let path_s = match unsafe { cstr_to_string(path, "path") } {
        Ok(s) => s,
        Err(code) => return code,
    };
    let old_pwd = match unsafe { cstr_to_string(old_password, "old_password") } {
        Ok(s) => s,
        Err(code) => return code,
    };
    let new_pwd = match unsafe { cstr_to_string(new_password, "new_password") } {
        Ok(s) => s,
        Err(code) => return code,
    };

    let ui = FfiUi { cb: progress_fn, user_data };
    match arsenic_rekey(
        Path::new(&path_s),
        &Secret::new(old_pwd),
        &Secret::new(new_pwd),
        &ui,
    ) {
        Ok(()) => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── File detection ────────────────────────────────────────────────────────────

/// Returns `1` if the file at `path` begins with the Arsenic V1 magic bytes,
/// `0` otherwise (including on error or null pointer).
///
/// # Safety
/// `path` must be a valid null-terminated C string, or null.
#[no_mangle]
pub unsafe extern "C" fn arsenic_is_arsenic_file(path: *const c_char) -> i32 {
    if path.is_null() {
        return 0;
    }
    let Ok(s) = (unsafe { CStr::from_ptr(path) }).to_str() else { return 0 };
    i32::from(is_arsenic_file(Path::new(s)))
}

// ── Cipher benchmark ──────────────────────────────────────────────────────────

/// Benchmark result for one AEAD cipher.
#[repr(C)]
pub struct ArsBenchResult {
    /// Cipher byte ID (matches `ArsParams.hdr_cipher` / `.pld_cipher`):
    /// `0x02` Deoxys-II-256 · `0x03` XChaCha20-Poly1305 · `0x04` AES-256-GCM-SIV.
    pub cipher_id: u8,
    /// Encryption throughput in MiB/s.
    pub encrypt_mibps: f64,
    /// Decryption throughput in MiB/s.
    pub decrypt_mibps: f64,
}

/// Array of benchmark results returned by `arsenic_bench`.
///
/// Free with `arsenic_free_bench_array`.
#[repr(C)]
pub struct ArsBenchArray {
    /// Pointer to `count` results sorted fastest-first.
    pub results: *mut ArsBenchResult,
    /// Number of elements in `results` (always 3 in the current implementation).
    pub count: usize,
}

/// Benchmark the three AEAD ciphers on `payload_mib` MiB of synthetic data
/// using a single Interactive Argon2id key derivation.
///
/// Returns an `ArsBenchArray` sorted fastest-first.
/// The caller must free it with `arsenic_free_bench_array`.
///
/// **Why only payload cipher?**
/// The header cipher encrypts only 32 bytes (the DEK), which takes nanoseconds
/// regardless of algorithm — its choice has no measurable effect on throughput.
/// Only the payload cipher (which processes the entire file) determines speed.
/// The benchmark therefore ranks payload ciphers; `arsenic_bench_best_combo`
/// recommends the same fastest cipher for both roles.
///
/// `payload_mib = 32` is a good default (fast, stable results).
#[no_mangle]
pub extern "C" fn arsenic_bench(payload_mib: usize) -> ArsBenchArray {
    let results = bench_cipher_combinations(payload_mib, &NoUi);
    let count = results.len();
    let mut out: Vec<ArsBenchResult> = results
        .into_iter()
        .map(|r| ArsBenchResult {
            cipher_id: r.cipher.to_byte(),
            encrypt_mibps: r.encrypt_mibps,
            decrypt_mibps: r.decrypt_mibps,
        })
        .collect();
    let ptr = out.as_mut_ptr();
    std::mem::forget(out);
    ArsBenchArray { results: ptr, count }
}

/// Free an `ArsBenchArray` returned by `arsenic_bench`.
///
/// # Safety
/// `arr` must have been returned by `arsenic_bench` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn arsenic_free_bench_array(arr: ArsBenchArray) {
    if arr.results.is_null() || arr.count == 0 {
        return;
    }
    drop(unsafe { Vec::from_raw_parts(arr.results, arr.count, arr.count) });
}

/// Write the recommended (hdr_cipher_id, pld_cipher_id) from a bench array to
/// `*hdr_out` and `*pld_out`.
///
/// The array must be sorted fastest-first (as returned by `arsenic_bench`).
/// Both outputs are set to the fastest cipher found (index 0).
///
/// # Safety
/// `arr.results` must point to `arr.count` valid `ArsBenchResult` values.
/// `hdr_out` and `pld_out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn arsenic_bench_best_combo(
    arr: *const ArsBenchArray,
    hdr_out: *mut u8,
    pld_out: *mut u8,
) {
    if arr.is_null() || hdr_out.is_null() || pld_out.is_null() {
        return;
    }
    let arr = unsafe { &*arr };
    if arr.results.is_null() || arr.count == 0 {
        return;
    }
    let best_id = unsafe { (*arr.results).cipher_id };
    unsafe { *hdr_out = best_id };
    unsafe { *pld_out = best_id };
}
