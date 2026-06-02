//! C-compatible FFI wrapper around `arsenic`.
//!
//! # Building
//! ```sh
//! cargo build --release -p cryptyrust_ffi
//! # outputs: target/release/libarsenic_ffi.so  (Linux)
//! #          target/release/libarsenic_ffi.a
//! ```
//!
//! # Generating the C header
//! ```sh
//! cargo install cbindgen
//! cbindgen --config ffi/cbindgen.toml --crate arsenic_ffi --output arsenic.h
//! ```
//!
//! # Key sizes
//! - Public key encoded:  `arsenic1{bech32}` — **60 chars** + null → 61 bytes min
//! - Private key encoded: `ARSENIC-SECRET-KEY-1{BECH32}` — **72 chars** + null → 73 bytes min
//! - Use 80-byte buffers for both to have a safe margin.
//!
//! # Recipients (asymmetric encryption)
//! Recipients are represented as a flat byte array: `n_recipients × 32` bytes.
//! Each 32-byte slice is an X25519 public key in raw binary form.

use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::os::raw::{c_char, c_void};
use std::path::Path;
use std::sync::OnceLock;

use arsenic::{
    arsenic_add_recipient, arsenic_find_matching_key, arsenic_find_slot_for_privkey_legacy,
    arsenic_list_recipients,
    arsenic_main_routine, arsenic_main_routine_with_key, arsenic_rekey,
    arsenic_remove_recipient, decrypt_arsenic, decrypt_arsenic_with_key,
    encode_privkey, encode_pubkey, decode_privkey, decode_pubkey,
    encode_mlkem_pubkey, decode_mlkem_pubkey,
    encrypt_arsenic, generate_x25519_keypair, hybrid_encapsulation_key,
    mlkem_seed_from_x25519, mlkem_encapsulation_key_768,
    is_arsenic_file, pubkey_from_privkey,
    bench_cipher_combinations,
    ArsenicParams, ArsenicStrength, CipherId, CoreErr, Direction, Secret, Ui,
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

/// Returns a pointer to the last error message (null-terminated UTF-8).
///
/// Valid until the next `arsenic_*` call on this thread.
/// Returns null if no error has occurred yet.
#[no_mangle]
pub extern "C" fn arsenic_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow().as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
    })
}

// ── Error codes ───────────────────────────────────────────────────────────────

pub const ARSENIC_OK: i32             =   0;
/// Wrong password, corrupted data, or AEAD authentication failure.
pub const ARSENIC_ERR_DECRYPT: i32    =  -1;
/// I/O error (file not found, permission denied, etc.).
pub const ARSENIC_ERR_IO: i32         =  -2;
/// Invalid parameter (unknown cipher ID, strength, etc.).
pub const ARSENIC_ERR_PARAMS: i32     =  -3;
/// File does not carry Arsenic magic bytes or has a bad version.
pub const ARSENIC_ERR_BAD_MAGIC: i32  =  -4;
/// A required pointer argument was null.
pub const ARSENIC_ERR_NULL_PTR: i32   =  -5;
/// Operation was cancelled by the caller via the progress callback.
pub const ARSENIC_ERR_CANCELLED: i32  =  -6;
/// No asymmetric keyslot matched the provided private key.
pub const ARSENIC_ERR_NO_ASYM_KEY: i32 = -7;
/// Unclassified error — call `arsenic_last_error()` for details.
pub const ARSENIC_ERR_UNKNOWN: i32    = -99;

fn core_err_code(e: &CoreErr) -> i32 {
    match e {
        CoreErr::DecryptionError | CoreErr::DecryptFail(_) => ARSENIC_ERR_DECRYPT,
        CoreErr::IOError(_) | CoreErr::ReadError { .. }    => ARSENIC_ERR_IO,
        CoreErr::Argon2Params | CoreErr::Argon2Hash
        | CoreErr::CreateCipher                            => ARSENIC_ERR_PARAMS,
        CoreErr::BadSignature | CoreErr::BadHeaderVersion  => ARSENIC_ERR_BAD_MAGIC,
        CoreErr::Cancelled                                 => ARSENIC_ERR_CANCELLED,
        CoreErr::NoAsymKeyFound                            => ARSENIC_ERR_NO_ASYM_KEY,
        _                                                  => ARSENIC_ERR_UNKNOWN,
    }
}

// ── Output buffer ─────────────────────────────────────────────────────────────

/// Heap-allocated byte buffer returned by `arsenic_encrypt` / `arsenic_decrypt`.
///
/// **Must** be released with `arsenic_free_buffer` exactly once.
/// `ptr` is null and `len` is 0 on error.
#[repr(C)]
pub struct ArsBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl ArsBuffer {
    fn from_vec(v: Vec<u8>) -> Self {
        let b = v.into_boxed_slice();
        let len = b.len();
        let ptr = Box::into_raw(b).cast::<u8>();
        Self { ptr, len }
    }
    fn null() -> Self { Self { ptr: std::ptr::null_mut(), len: 0 } }
}

/// Free a buffer previously returned by any `arsenic_*` in-memory function.
///
/// # Safety
/// `buf` must be null or a valid `ArsBuffer` produced by this library, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn arsenic_free_buffer(buf: *mut ArsBuffer) {
    if buf.is_null() { return; }
    let b = unsafe { &mut *buf };
    if !b.ptr.is_null() && b.len > 0 {
        drop(unsafe { Box::from_raw(std::slice::from_raw_parts_mut(b.ptr, b.len)) });
        b.ptr = std::ptr::null_mut();
        b.len = 0;
    }
}

// ── Public-key array ──────────────────────────────────────────────────────────

/// Flat array of X25519 public keys (32 bytes each) returned by
/// `arsenic_list_recipients_file`.  Free with `arsenic_free_pubkey_array`.
#[repr(C)]
pub struct ArsPubKeyArray {
    /// Flat array of `count × 32` bytes (tightly packed).
    pub data: *mut u8,
    pub count: usize,
}

impl ArsPubKeyArray {
    fn from_keys(keys: Vec<[u8; 32]>) -> Self {
        if keys.is_empty() {
            return Self { data: std::ptr::null_mut(), count: 0 };
        }
        let flat: Vec<u8> = keys.into_iter().flatten().collect();
        let b = flat.into_boxed_slice();
        let count = b.len() / 32;
        let data = Box::into_raw(b).cast::<u8>();
        Self { data, count }
    }
    fn null() -> Self { Self { data: std::ptr::null_mut(), count: 0 } }
}

/// Free an `ArsPubKeyArray` returned by `arsenic_list_recipients_file`.
///
/// # Safety
/// `arr` must have been returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn arsenic_free_pubkey_array(arr: *mut ArsPubKeyArray) {
    if arr.is_null() { return; }
    let a = unsafe { &mut *arr };
    if !a.data.is_null() && a.count > 0 {
        drop(unsafe { Box::from_raw(std::slice::from_raw_parts_mut(a.data, a.count * 32)) });
        a.data = std::ptr::null_mut();
        a.count = 0;
    }
}

// ── Parameters ────────────────────────────────────────────────────────────────

/// Encryption parameters.
///
/// **Cipher IDs** (header byte value):
/// - `0x02` Deoxys-II-256           (default header cipher)
/// - `0x03` XChaCha20-Poly1305      (default payload cipher)
/// - `0x04` AES-256-GCM-SIV
///
/// **`strength`** — Argon2id cost preset:
/// - `0` Interactive  (256 MiB, ~1–3 s)
/// - `1` Sensitive    (1 GiB,  ~10–30 s)
#[repr(C)]
pub struct ArsParams {
    pub hdr_cipher: u8,
    pub pld_cipher: u8,
    pub strength:   u8,
}

/// Returns default parameters: Deoxys-II-256 header · XChaCha20-Poly1305 payload · Interactive.
#[no_mangle]
pub extern "C" fn arsenic_default_params() -> ArsParams {
    ArsParams { hdr_cipher: 0x02, pld_cipher: 0x03, strength: 0 }
}

fn to_core_params(p: &ArsParams, recipients: Vec<arsenic::HybridRecipient>) -> Result<ArsenicParams, i32> {
    let hdr = CipherId::from_byte(p.hdr_cipher).map_err(|_| ARSENIC_ERR_PARAMS)?;
    let pld = CipherId::from_byte(p.pld_cipher).map_err(|_| ARSENIC_ERR_PARAMS)?;
    let strength = match p.strength {
        0 => ArsenicStrength::Interactive,
        1 => ArsenicStrength::Sensitive,
        _ => return Err(ARSENIC_ERR_PARAMS),
    };
    Ok(ArsenicParams { hdr_cipher: hdr, pld_cipher: pld, recipients, ..ArsenicParams::from(strength) })
}

// ── KDF params from file ──────────────────────────────────────────────────────

/// KDF and cipher parameters as read from an Arsenic file header.
#[repr(C)]
pub struct ArsKdfParams {
    pub t_cost:     u32,
    pub m_cost_kib: u32,
    pub p_cost:     u32,
    pub hdr_cipher: u8,
    pub pld_cipher: u8,
}

/// Read the Argon2id and cipher parameters from an existing Arsenic file.
///
/// Returns `ARSENIC_OK` on success; fills `*out`.
/// Returns `ARSENIC_ERR_BAD_MAGIC` if the file is not a valid Arsenic file.
///
/// # Safety
/// `path` and `out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn arsenic_read_params_file(
    path: *const c_char,
    out:  *mut ArsKdfParams,
) -> i32 {
    if out.is_null() { set_last_error("out is null"); return ARSENIC_ERR_NULL_PTR; }
    let path_s = match unsafe { cstr_to_string(path, "path") } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match arsenic::arsenic_read_params(Path::new(&path_s)) {
        None => { set_last_error("not a valid Arsenic file"); ARSENIC_ERR_BAD_MAGIC }
        Some(p) => {
            unsafe { *out = ArsKdfParams {
                t_cost:     p.t_cost,
                m_cost_kib: p.m_cost,
                p_cost:     p.p_cost,
                hdr_cipher: p.hdr_cipher.to_byte(),
                pld_cipher: p.pld_cipher.to_byte(),
            }};
            ARSENIC_OK
        }
    }
}

// ── Progress callback ─────────────────────────────────────────────────────────

/// Optional progress callback. `percentage` is 0–100. Pass null to ignore.
pub type ArsProgressFn =
    Option<unsafe extern "C" fn(percentage: i32, user_data: *mut c_void)>;

struct FfiUi { cb: ArsProgressFn, user_data: *mut c_void }
unsafe impl Send for FfiUi {}
unsafe impl Sync for FfiUi {}
impl Ui for FfiUi {
    fn output(&self, pct: i32) {
        if let Some(f) = self.cb { unsafe { f(pct, self.user_data) }; }
    }
}

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// Parse a flat `recipients` byte array into `Vec<HybridRecipient>`.
///
/// Each recipient is 1216 bytes: x25519_pk[32] || mlkem_pk[1184].
/// Returns `Err(ARSENIC_ERR_NULL_PTR)` if the pointer is null and n > 0.
unsafe fn parse_recipients(ptr: *const u8, n: usize) -> Result<Vec<arsenic::HybridRecipient>, i32> {
    const RECIP_LEN: usize = 32 + 1184;
    if n == 0 { return Ok(vec![]); }
    if ptr.is_null() {
        set_last_error("recipients is null but n_recipients > 0");
        return Err(ARSENIC_ERR_NULL_PTR);
    }
    let flat = unsafe { std::slice::from_raw_parts(ptr, n * RECIP_LEN) };
    Ok(flat.chunks_exact(RECIP_LEN).map(|c| {
        let x25519: [u8; 32] = c[..32].try_into().unwrap();
        let mlkem: [u8; 1184] = c[32..].try_into().unwrap();
        arsenic::HybridRecipient::new(x25519, mlkem)
    }).collect())
}

// ── In-memory encrypt ─────────────────────────────────────────────────────────

/// Encrypt a plaintext buffer in memory.
///
/// `recipients` is a flat array of `n_recipients × 32` bytes (raw X25519 public
/// keys).  Pass null / 0 for password-only encryption.
/// If `n_recipients > 0` and `password` is null or empty, a random KEK is used
/// (symmetric slot inaccessible; only recipients can decrypt).
///
/// On success writes ciphertext to `*out`; caller must free with
/// `arsenic_free_buffer`.
///
/// # Safety
/// All non-null pointer arguments must be valid for the described lengths.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encrypt(
    plaintext:     *const u8,
    plaintext_len: usize,
    password:      *const c_char,
    params:        *const ArsParams,
    recipients:    *const u8,
    n_recipients:  usize,
    progress_fn:   ArsProgressFn,
    user_data:     *mut c_void,
    out:           *mut ArsBuffer,
) -> i32 {
    if out.is_null() { set_last_error("out is null"); return ARSENIC_ERR_NULL_PTR; }
    unsafe { *out = ArsBuffer::null() };
    if plaintext.is_null() || params.is_null() {
        set_last_error("null pointer argument"); return ARSENIC_ERR_NULL_PTR;
    }

    let pwd = if password.is_null() || unsafe { CStr::from_ptr(password) }.to_bytes().is_empty() {
        // No password — random KEK if recipients are present
        let r = arsenic::random_bytes_32();
        r.iter().map(|b| format!("{b:02x}")).collect::<String>()
    } else {
        match unsafe { cstr_to_string(password, "password") } {
            Ok(s) => s,
            Err(code) => return code,
        }
    };

    let recips = match unsafe { parse_recipients(recipients, n_recipients) } {
        Ok(v) => v, Err(code) => return code,
    };
    let core_params = match to_core_params(unsafe { &*params }, recips) {
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
        Ok(()) => { unsafe { *out = ArsBuffer::from_vec(output.into_inner()) }; ARSENIC_OK }
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── In-memory decrypt (symmetric) ────────────────────────────────────────────

/// Decrypt a ciphertext buffer in memory using a password.
///
/// Cipher parameters are read from the header — no `ArsParams` needed.
///
/// # Safety
/// All non-null pointer arguments must be valid.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decrypt(
    ciphertext:     *const u8,
    ciphertext_len: usize,
    password:       *const c_char,
    progress_fn:    ArsProgressFn,
    user_data:      *mut c_void,
    out:            *mut ArsBuffer,
) -> i32 {
    if out.is_null() { set_last_error("out is null"); return ARSENIC_ERR_NULL_PTR; }
    unsafe { *out = ArsBuffer::null() };
    if ciphertext.is_null() { set_last_error("ciphertext is null"); return ARSENIC_ERR_NULL_PTR; }

    let pwd = match unsafe { cstr_to_string(password, "password") } {
        Ok(s) => s, Err(code) => return code,
    };
    let data = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::new());
    let ui = FfiUi { cb: progress_fn, user_data };

    match decrypt_arsenic(&mut input, &mut output, &Secret::new(pwd), &ui, ciphertext_len as u64) {
        Ok(_) => { unsafe { *out = ArsBuffer::from_vec(output.into_inner()) }; ARSENIC_OK }
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── In-memory decrypt (asymmetric) ───────────────────────────────────────────

/// Decrypt a ciphertext buffer in memory using a 32-byte X25519 private key.
///
/// Returns `ARSENIC_ERR_NO_ASYM_KEY` if the key does not match any keyslot.
///
/// # Safety
/// `privkey` must point to exactly 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decrypt_with_key(
    ciphertext:     *const u8,
    ciphertext_len: usize,
    privkey:        *const u8,
    progress_fn:    ArsProgressFn,
    user_data:      *mut c_void,
    out:            *mut ArsBuffer,
) -> i32 {
    if out.is_null() { set_last_error("out is null"); return ARSENIC_ERR_NULL_PTR; }
    unsafe { *out = ArsBuffer::null() };
    if ciphertext.is_null() || privkey.is_null() {
        set_last_error("null pointer argument"); return ARSENIC_ERR_NULL_PTR;
    }

    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }
        .try_into().expect("exactly 32 bytes");
    let data = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::new());
    let ui = FfiUi { cb: progress_fn, user_data };

    let mlkem_seed = mlkem_seed_from_x25519(&pk);
    match decrypt_arsenic_with_key(&mut input, &mut output, &Secret::new(pk), &mlkem_seed, &ui, ciphertext_len as u64) {
        Ok(_) => { unsafe { *out = ArsBuffer::from_vec(output.into_inner()) }; ARSENIC_OK }
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── File-based encrypt ────────────────────────────────────────────────────────

/// Encrypt a file, writing the result to `path_out`.
///
/// `recipients` / `n_recipients`: same semantics as `arsenic_encrypt`.
///
/// # Safety
/// All pointer arguments must be valid null-terminated C strings or null.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encrypt_file(
    path_in:      *const c_char,
    path_out:     *const c_char,
    password:     *const c_char,
    params:       *const ArsParams,
    recipients:   *const u8,
    n_recipients: usize,
    progress_fn:  ArsProgressFn,
    user_data:    *mut c_void,
) -> i32 {
    if params.is_null() { set_last_error("params is null"); return ARSENIC_ERR_NULL_PTR; }

    let in_s  = match unsafe { cstr_to_string(path_in,  "path_in")  } { Ok(s) => s, Err(c) => return c };
    let out_s = match unsafe { cstr_to_string(path_out, "path_out") } { Ok(s) => s, Err(c) => return c };

    let pwd = if password.is_null() || unsafe { CStr::from_ptr(password) }.to_bytes().is_empty() {
        let r = arsenic::random_bytes_32();
        r.iter().map(|b| format!("{b:02x}")).collect::<String>()
    } else {
        match unsafe { cstr_to_string(password, "password") } { Ok(s) => s, Err(c) => return c }
    };

    let recips = match unsafe { parse_recipients(recipients, n_recipients) } { Ok(v) => v, Err(c) => return c };
    let core_params = match to_core_params(unsafe { &*params }, recips) {
        Ok(p) => p, Err(c) => { set_last_error("invalid params"); return c; }
    };
    let ui = Box::new(FfiUi { cb: progress_fn, user_data });

    match arsenic_main_routine(
        &Direction::Encrypt,
        Some(&in_s), Some(&out_s),
        &Secret::new(pwd), ui,
        Some(core_params),
    ) {
        Ok(_)  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── File-based decrypt (symmetric) ───────────────────────────────────────────

/// Decrypt an Arsenic file using a password, writing plaintext to `path_out`.
///
/// # Safety
/// All pointer arguments must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decrypt_file(
    path_in:     *const c_char,
    path_out:    *const c_char,
    password:    *const c_char,
    progress_fn: ArsProgressFn,
    user_data:   *mut c_void,
) -> i32 {
    let in_s  = match unsafe { cstr_to_string(path_in,  "path_in")  } { Ok(s) => s, Err(c) => return c };
    let out_s = match unsafe { cstr_to_string(path_out, "path_out") } { Ok(s) => s, Err(c) => return c };
    let pwd   = match unsafe { cstr_to_string(password, "password") } { Ok(s) => s, Err(c) => return c };
    let ui    = Box::new(FfiUi { cb: progress_fn, user_data });

    match arsenic_main_routine(
        &Direction::Decrypt,
        Some(&in_s), Some(&out_s),
        &Secret::new(pwd), ui, None,
    ) {
        Ok(_)  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── File-based decrypt (asymmetric) ──────────────────────────────────────────

/// Decrypt an Arsenic file using a 32-byte X25519 private key.
///
/// Returns `ARSENIC_ERR_NO_ASYM_KEY` if the key does not match any keyslot.
///
/// # Safety
/// `privkey` must point to exactly 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decrypt_file_with_key(
    path_in:     *const c_char,
    path_out:    *const c_char,
    privkey:     *const u8,
    progress_fn: ArsProgressFn,
    user_data:   *mut c_void,
) -> i32 {
    if privkey.is_null() { set_last_error("privkey is null"); return ARSENIC_ERR_NULL_PTR; }
    let in_s  = match unsafe { cstr_to_string(path_in,  "path_in")  } { Ok(s) => s, Err(c) => return c };
    let out_s = match unsafe { cstr_to_string(path_out, "path_out") } { Ok(s) => s, Err(c) => return c };
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }
        .try_into().expect("32 bytes");
    let ui = Box::new(FfiUi { cb: progress_fn, user_data });

    let mlkem_seed = mlkem_seed_from_x25519(&pk);
    let key = arsenic::keystore::KeyEntry {
        name: String::new(),
        private_key: pk,
        mlkem_seed,
        public_key: pubkey_from_privkey(&pk),
        mlkem_public_key: Box::new(mlkem_encapsulation_key_768(&mlkem_seed)),
        file_path: None,
    };
    match arsenic_main_routine_with_key(Some(&in_s), Some(&out_s), &key, ui) {
        Ok(_)  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── Rekey ─────────────────────────────────────────────────────────────────────

/// Change the password of an Arsenic file in-place.
///
/// A crash-safe `.bak` backup is written before the in-place write and removed
/// on success.
///
/// # Safety
/// All pointer arguments must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn arsenic_rekey_file(
    path:         *const c_char,
    old_password: *const c_char,
    new_password: *const c_char,
    progress_fn:  ArsProgressFn,
    user_data:    *mut c_void,
) -> i32 {
    let path_s  = match unsafe { cstr_to_string(path,         "path")         } { Ok(s) => s, Err(c) => return c };
    let old_pwd = match unsafe { cstr_to_string(old_password, "old_password") } { Ok(s) => s, Err(c) => return c };
    let new_pwd = match unsafe { cstr_to_string(new_password, "new_password") } { Ok(s) => s, Err(c) => return c };
    let ui = FfiUi { cb: progress_fn, user_data };

    match arsenic_rekey(Path::new(&path_s), &Secret::new(old_pwd), &Secret::new(new_pwd), &ui) {
        Ok(())  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

// ── File detection ────────────────────────────────────────────────────────────

/// Returns `1` if the file begins with the Arsenic magic bytes, `0` otherwise.
///
/// # Safety
/// `path` must be a valid null-terminated C string, or null.
#[no_mangle]
pub unsafe extern "C" fn arsenic_is_arsenic_file(path: *const c_char) -> i32 {
    if path.is_null() { return 0; }
    let Ok(s) = (unsafe { CStr::from_ptr(path) }).to_str() else { return 0 };
    i32::from(is_arsenic_file(Path::new(s)))
}

// ── Recipient management ──────────────────────────────────────────────────────

/// List the ephemeral X25519 public keys of all asymmetric keyslots in a file.
///
/// The returned array must be freed with `arsenic_free_pubkey_array`.
/// On error the array has `data = null, count = 0`; check `arsenic_last_error()`.
///
/// Note: these are the *ephemeral* keys used for ECDH, not the recipients'
/// own public keys.
///
/// # Safety
/// `path` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn arsenic_list_recipients_file(path: *const c_char) -> ArsPubKeyArray {
    let Ok(s) = (unsafe { cstr_to_string(path, "path") }) else { return ArsPubKeyArray::null() };
    match arsenic_list_recipients(Path::new(&s)) {
        Ok(keys) => ArsPubKeyArray::from_keys(keys),
        Err(e) => { set_last_error(&e); ArsPubKeyArray::null() }
    }
}

/// Add a hybrid (X25519 + ML-KEM-768) keyslot to a file.
///
/// `recipient` must point to 1216 bytes: x25519_pk[32] || mlkem_ek[1184].
/// Requires the symmetric `password` to authenticate the header.
/// The payload is not re-encrypted.
///
/// # Safety
/// `recipient` must point to exactly 1216 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_add_recipient_file(
    path:        *const c_char,
    password:    *const c_char,
    recipient:   *const u8,
    progress_fn: ArsProgressFn,
    user_data:   *mut c_void,
) -> i32 {
    if recipient.is_null() { set_last_error("recipient is null"); return ARSENIC_ERR_NULL_PTR; }
    let path_s = match unsafe { cstr_to_string(path,     "path")     } { Ok(s) => s, Err(c) => return c };
    let pwd    = match unsafe { cstr_to_string(password, "password") } { Ok(s) => s, Err(c) => return c };
    let raw = unsafe { std::slice::from_raw_parts(recipient, 1216) };
    let x25519: [u8; 32]   = raw[..32].try_into().expect("32 bytes");
    let mlkem:  [u8; 1184] = raw[32..].try_into().expect("1184 bytes");
    let recip = arsenic::HybridRecipient::new(x25519, mlkem);
    let ui = FfiUi { cb: progress_fn, user_data };

    match arsenic_add_recipient(Path::new(&path_s), &Secret::new(pwd), &recip, &ui) {
        Ok(())  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

/// Remove the asymmetric keyslot at position `index` (0-based) from a file.
///
/// Requires the symmetric `password`.  The payload is not re-encrypted.
///
/// # Safety
/// All pointer arguments must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn arsenic_remove_recipient_file(
    path:        *const c_char,
    password:    *const c_char,
    index:       usize,
    progress_fn: ArsProgressFn,
    user_data:   *mut c_void,
) -> i32 {
    let path_s = match unsafe { cstr_to_string(path,     "path")     } { Ok(s) => s, Err(c) => return c };
    let pwd    = match unsafe { cstr_to_string(password, "password") } { Ok(s) => s, Err(c) => return c };
    let ui = FfiUi { cb: progress_fn, user_data };

    match arsenic_remove_recipient(Path::new(&path_s), &Secret::new(pwd), index, &ui) {
        Ok(())  => ARSENIC_OK,
        Err(e) => { set_last_error(&e); core_err_code(&e) }
    }
}

/// Find which of the provided private keys (if any) can decrypt the file.
///
/// `privkeys` is a flat array of `n_keys × 32` bytes.
///
/// Returns the 0-based index of the first matching key, or `-1` if none match
/// (including file-not-found and parse errors).
///
/// # Safety
/// `privkeys` must point to `n_keys × 32` readable bytes (or be null if n_keys == 0).
#[no_mangle]
pub unsafe extern "C" fn arsenic_find_matching_key_file(
    path:     *const c_char,
    privkeys: *const u8,
    n_keys:   usize,
) -> i32 {
    if n_keys == 0 { return -1; }
    let Ok(path_s) = (unsafe { cstr_to_string(path, "path") }) else { return -1 };
    if privkeys.is_null() { return -1; }
    let flat = unsafe { std::slice::from_raw_parts(privkeys, n_keys * 32) };
    let keys: Vec<arsenic::keystore::KeyEntry> = flat.chunks_exact(32)
        .map(|c| {
            let pk: [u8; 32] = c.try_into().unwrap();
            let mlkem_seed = mlkem_seed_from_x25519(&pk);
            arsenic::keystore::KeyEntry {
                name: String::new(),
                private_key: pk,
                mlkem_seed,
                public_key: pubkey_from_privkey(&pk),
                mlkem_public_key: Box::new(mlkem_encapsulation_key_768(&mlkem_seed)),
                file_path: None,
            }
        })
        .collect();
    match arsenic_find_matching_key(Path::new(&path_s), &keys) {
        Some(idx) => idx as i32,
        None      => -1,
    }
}

/// Find which **keyslot index** (position in the file's keyslot array) can be
/// opened with `privkey` (32 bytes).
///
/// Returns the 0-based slot index on success, or `-1` if no slot matches, the file
/// has no asymmetric keyslots, or an error occurred.
///
/// Unlike `arsenic_find_matching_key_file` (which returns the index into the *privkeys*
/// array), this returns the slot position inside the file — the value to pass to
/// `arsenic_remove_recipient_file`.  No symmetric password is required.
///
/// # Safety
/// `path` must be a valid null-terminated C string; `privkey` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_find_slot_for_key_file(
    path:    *const c_char,
    privkey: *const u8,
) -> i32 {
    if privkey.is_null() { return -1; }
    let Ok(path_s) = (unsafe { cstr_to_string(path, "path") }) else { return -1 };
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }
        .try_into().expect("32 bytes");
    match arsenic_find_slot_for_privkey_legacy(Path::new(&path_s), &pk) {
        Some(idx) => idx as i32,
        None      => -1,
    }
}

// ── Key utilities ─────────────────────────────────────────────────────────────

/// Generate a fresh X25519 keypair.
///
/// Writes 32 bytes to `privkey_out` and 32 bytes to `pubkey_out`.
///
/// # Safety
/// Both pointers must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_generate_keypair(
    privkey_out: *mut u8,
    pubkey_out:  *mut u8,
) {
    if privkey_out.is_null() || pubkey_out.is_null() { return; }
    let (priv_bytes, pub_bytes) = generate_x25519_keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(priv_bytes.as_ptr(), privkey_out, 32);
        std::ptr::copy_nonoverlapping(pub_bytes.as_ptr(),  pubkey_out,  32);
    }
}

/// Derive the X25519 public key from a 32-byte private key.
///
/// # Safety
/// `privkey` must point to exactly 32 readable bytes; `pubkey_out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_pubkey_from_privkey(
    privkey:    *const u8,
    pubkey_out: *mut u8,
) {
    if privkey.is_null() || pubkey_out.is_null() { return; }
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }.try_into().expect("32 bytes");
    let pub_bytes = pubkey_from_privkey(&pk);
    unsafe { std::ptr::copy_nonoverlapping(pub_bytes.as_ptr(), pubkey_out, 32) };
}

/// Derive the 1216-byte hybrid public key (x25519[32] || mlkem_ek[1184]) from a 32-byte private key.
///
/// The result is suitable for use as a `recipients` element in `arsenic_encrypt` /
/// `arsenic_encrypt_file` (which expect 1216 bytes per recipient).
///
/// # Safety
/// `privkey` must point to exactly 32 readable bytes; `hybrid_out` to 1216 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_hybrid_pubkey(privkey: *const u8, hybrid_out: *mut u8) {
    if privkey.is_null() || hybrid_out.is_null() { return; }
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }.try_into().expect("32 bytes");
    let x25519_pub = pubkey_from_privkey(&pk);
    let mlkem_seed = mlkem_seed_from_x25519(&pk);
    let mlkem_ek = hybrid_encapsulation_key(&mlkem_seed);
    unsafe {
        std::ptr::copy_nonoverlapping(x25519_pub.as_ptr(), hybrid_out, 32);
        std::ptr::copy_nonoverlapping(mlkem_ek.as_ptr(), hybrid_out.add(32), 1184);
    }
}

/// Encode a 32-byte public key as a null-terminated `arsenic1…` string (60 chars).
///
/// Writes at most `buf_len` bytes (including the null terminator) to `buf`.
/// Returns the number of bytes written (excluding null) or 0 on error.
/// Requires `buf_len >= 61`.
///
/// # Safety
/// `pubkey` must point to exactly 32 readable bytes; `buf` to `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encode_pubkey(
    pubkey:  *const u8,
    buf:     *mut c_char,
    buf_len: usize,
) -> usize {
    if pubkey.is_null() || buf.is_null() || buf_len < 61 { return 0; }
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(pubkey, 32) }.try_into().expect("32 bytes");
    let encoded = encode_pubkey(&pk);
    let bytes = encoded.as_bytes();
    let n = bytes.len().min(buf_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, n);
        *buf.add(n) = 0;
    }
    n
}

/// Decode an `arsenic1…` string into a 32-byte public key.
///
/// Returns `1` on success (writes 32 bytes to `pubkey_out`), `0` on failure.
///
/// # Safety
/// `encoded` must be a valid null-terminated C string; `pubkey_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decode_pubkey(
    encoded:    *const c_char,
    pubkey_out: *mut u8,
) -> i32 {
    if encoded.is_null() || pubkey_out.is_null() { return 0; }
    let Ok(s) = (unsafe { CStr::from_ptr(encoded) }).to_str() else { return 0 };
    match decode_pubkey(s) {
        Some(pk) => {
            unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), pubkey_out, 32) };
            1
        }
        None => 0,
    }
}

/// Encode a 32-byte private key as a null-terminated `ARSENIC-SECRET-KEY-1…` string (72 chars).
///
/// Requires `buf_len >= 73`.
/// Returns the number of bytes written (excluding null) or 0 on error.
///
/// # Safety
/// `privkey` must point to exactly 32 readable bytes; `buf` to `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encode_privkey(
    privkey: *const u8,
    buf:     *mut c_char,
    buf_len: usize,
) -> usize {
    if privkey.is_null() || buf.is_null() || buf_len < 73 { return 0; }
    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }.try_into().expect("32 bytes");
    let encoded = encode_privkey(&pk);
    let bytes = encoded.as_bytes();
    let n = bytes.len().min(buf_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, n);
        *buf.add(n) = 0;
    }
    n
}

/// Decode an `ARSENIC-SECRET-KEY-1…` string into a 32-byte private key.
///
/// Returns `1` on success, `0` on failure.
///
/// # Safety
/// `encoded` must be a valid null-terminated C string; `privkey_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decode_privkey(
    encoded:     *const c_char,
    privkey_out: *mut u8,
) -> i32 {
    if encoded.is_null() || privkey_out.is_null() { return 0; }
    let Ok(s) = (unsafe { CStr::from_ptr(encoded) }).to_str() else { return 0 };
    match decode_privkey(s) {
        Some(pk) => {
            unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), privkey_out, 32) };
            1
        }
        None => 0,
    }
}

/// Encode a 1184-byte ML-KEM-768 encapsulation key as a null-terminated `arsenic1m…` string.
///
/// The buffer must be at least 1956 bytes (1955 chars + null). Returns the number of bytes
/// written (excluding null), or 0 on error.
///
/// # Safety
/// `ek` must point to 1184 readable bytes; `buf` to `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_encode_mlkem_pubkey(
    ek:      *const u8,
    buf:     *mut c_char,
    buf_len: usize,
) -> usize {
    if ek.is_null() || buf.is_null() || buf_len < 1956 { return 0; }
    let ek: [u8; 1184] = unsafe { std::slice::from_raw_parts(ek, 1184) }.try_into().expect("1184 bytes");
    let encoded = encode_mlkem_pubkey(&ek);
    let bytes = encoded.as_bytes();
    let n = bytes.len().min(buf_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, n);
        *buf.add(n) = 0;
    }
    n
}

/// Decode an `arsenic1m…` string into a 1184-byte ML-KEM-768 encapsulation key.
///
/// Returns `1` on success (writes 1184 bytes to `ek_out`), `0` on failure.
///
/// # Safety
/// `encoded` must be a valid null-terminated C string; `ek_out` must point to 1184 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn arsenic_decode_mlkem_pubkey(
    encoded: *const c_char,
    ek_out:  *mut u8,
) -> i32 {
    if encoded.is_null() || ek_out.is_null() { return 0; }
    let Ok(s) = (unsafe { CStr::from_ptr(encoded) }).to_str() else { return 0 };
    match decode_mlkem_pubkey(s) {
        Some(ek) => {
            unsafe { std::ptr::copy_nonoverlapping(ek.as_ptr(), ek_out, 1184) };
            1
        }
        None => 0,
    }
}

// ── Version ───────────────────────────────────────────────────────────────────

/// Returns the library version string (e.g. `"1.3.2"`).
/// The pointer is valid for the lifetime of the process.
#[no_mangle]
pub extern "C" fn arsenic_version() -> *const c_char {
    static V: OnceLock<CString> = OnceLock::new();
    V.get_or_init(|| CString::new(arsenic::get_version()).unwrap_or_default()).as_ptr()
}

// ── Cipher benchmark ──────────────────────────────────────────────────────────

/// Benchmark result for one AEAD cipher.
#[repr(C)]
pub struct ArsBenchResult {
    /// Cipher byte ID: `0x02` Deoxys-II · `0x03` XChaCha20 · `0x04` AES-GCM-SIV.
    pub cipher_id:      u8,
    pub encrypt_mibps:  f64,
    pub decrypt_mibps:  f64,
}

/// Array of benchmark results (sorted fastest-first). Free with `arsenic_free_bench_array`.
#[repr(C)]
pub struct ArsBenchArray {
    pub results: *mut ArsBenchResult,
    pub count:   usize,
}

/// Benchmark the three AEAD ciphers on `payload_mib` MiB of synthetic data.
/// Returns an `ArsBenchArray` sorted fastest-first. Free with `arsenic_free_bench_array`.
/// `payload_mib = 32` is a good default.
#[no_mangle]
pub extern "C" fn arsenic_bench(payload_mib: usize) -> ArsBenchArray {
    let results = bench_cipher_combinations(payload_mib, &NoUi);
    let count = results.len();
    let mut out: Vec<ArsBenchResult> = results
        .into_iter()
        .map(|r| ArsBenchResult { cipher_id: r.cipher.to_byte(), encrypt_mibps: r.encrypt_mibps, decrypt_mibps: r.decrypt_mibps })
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
    if arr.results.is_null() || arr.count == 0 { return; }
    drop(unsafe { Vec::from_raw_parts(arr.results, arr.count, arr.count) });
}

/// Write the recommended (hdr_cipher_id, pld_cipher_id) to `*hdr_out` / `*pld_out`.
///
/// # Safety
/// All pointers must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn arsenic_bench_best_combo(
    arr:     *const ArsBenchArray,
    hdr_out: *mut u8,
    pld_out: *mut u8,
) {
    if arr.is_null() || hdr_out.is_null() || pld_out.is_null() { return; }
    let arr = unsafe { &*arr };
    if arr.results.is_null() || arr.count == 0 { return; }
    let best_id = unsafe { (*arr.results).cipher_id };
    unsafe { *hdr_out = best_id; *pld_out = best_id; }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn cstr(s: &str) -> CString { CString::new(s).unwrap() }

    fn default_params() -> ArsParams { arsenic_default_params() }

    /// Round-trip encrypt + decrypt in memory (symmetric).
    fn mem_roundtrip(plaintext: &[u8], password: &str) -> Vec<u8> {
        let pwd  = cstr(password);
        let p    = default_params();
        let mut ct_buf = ArsBuffer::null();
        let rc = unsafe {
            arsenic_encrypt(
                plaintext.as_ptr(), plaintext.len(),
                pwd.as_ptr(), &p,
                std::ptr::null(), 0,
                None, std::ptr::null_mut(),
                &mut ct_buf,
            )
        };
        assert_eq!(rc, ARSENIC_OK);
        assert!(!ct_buf.ptr.is_null());

        let mut pt_buf = ArsBuffer::null();
        let rc2 = unsafe {
            arsenic_decrypt(
                ct_buf.ptr, ct_buf.len,
                pwd.as_ptr(),
                None, std::ptr::null_mut(),
                &mut pt_buf,
            )
        };
        assert_eq!(rc2, ARSENIC_OK, "decrypt failed");
        let result = unsafe { std::slice::from_raw_parts(pt_buf.ptr, pt_buf.len).to_vec() };
        unsafe { arsenic_free_buffer(&mut ct_buf); arsenic_free_buffer(&mut pt_buf); }
        result
    }

    // ── In-memory symmetric ───────────────────────────────────────────────────

    #[test]
    fn mem_encrypt_decrypt_empty() {
        assert_eq!(mem_roundtrip(b"", "secret123"), b"");
    }

    #[test]
    fn mem_encrypt_decrypt_small() {
        let plain = b"Hello, Arsenic FFI!";
        assert_eq!(mem_roundtrip(plain, "password123"), plain);
    }

    #[test]
    fn mem_encrypt_decrypt_binary() {
        let plain: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert_eq!(mem_roundtrip(&plain, "test_pw"), plain);
    }

    #[test]
    fn mem_decrypt_wrong_password_fails() {
        let pwd  = cstr("right_password");
        let wrong = cstr("wrong_password");
        let p    = default_params();
        let plain = b"secret";
        let mut ct_buf = ArsBuffer::null();
        let rc = unsafe {
            arsenic_encrypt(plain.as_ptr(), plain.len(), pwd.as_ptr(), &p,
                            std::ptr::null(), 0, None, std::ptr::null_mut(), &mut ct_buf)
        };
        assert_eq!(rc, ARSENIC_OK);

        let mut pt_buf = ArsBuffer::null();
        let rc2 = unsafe {
            arsenic_decrypt(ct_buf.ptr, ct_buf.len, wrong.as_ptr(),
                            None, std::ptr::null_mut(), &mut pt_buf)
        };
        assert_eq!(rc2, ARSENIC_ERR_DECRYPT);
        assert!(pt_buf.ptr.is_null());
        unsafe { arsenic_free_buffer(&mut ct_buf); }
    }

    // ── In-memory asymmetric ──────────────────────────────────────────────────

    /// Helper: derive the 1216-byte hybrid public key from a 32-byte private key.
    unsafe fn get_hybrid_pubkey(priv_bytes: &[u8; 32]) -> [u8; 1216] {
        let mut hybrid = [0u8; 1216];
        unsafe { arsenic_hybrid_pubkey(priv_bytes.as_ptr(), hybrid.as_mut_ptr()) };
        hybrid
    }

    #[test]
    fn mem_asym_encrypt_decrypt() {
        let mut priv_bytes = [0u8; 32];
        let mut _pub_x25519 = [0u8; 32];
        unsafe { arsenic_generate_keypair(priv_bytes.as_mut_ptr(), _pub_x25519.as_mut_ptr()) };
        let hybrid_pk = unsafe { get_hybrid_pubkey(&priv_bytes) };

        let plain = b"asymmetric test payload";
        let p = default_params();
        let mut ct_buf = ArsBuffer::null();
        let rc = unsafe {
            arsenic_encrypt(
                plain.as_ptr(), plain.len(),
                std::ptr::null(), &p,
                hybrid_pk.as_ptr(), 1,   // 1 hybrid recipient = 1216 bytes
                None, std::ptr::null_mut(), &mut ct_buf,
            )
        };
        assert_eq!(rc, ARSENIC_OK);

        let mut pt_buf = ArsBuffer::null();
        let rc2 = unsafe {
            arsenic_decrypt_with_key(
                ct_buf.ptr, ct_buf.len,
                priv_bytes.as_ptr(),
                None, std::ptr::null_mut(), &mut pt_buf,
            )
        };
        assert_eq!(rc2, ARSENIC_OK);
        let result = unsafe { std::slice::from_raw_parts(pt_buf.ptr, pt_buf.len) };
        assert_eq!(result, plain);
        unsafe { arsenic_free_buffer(&mut ct_buf); arsenic_free_buffer(&mut pt_buf); }
    }

    #[test]
    fn mem_asym_wrong_key_fails() {
        let mut priv1 = [0u8; 32]; let mut priv2 = [0u8; 32];
        let mut _x1 = [0u8; 32]; let mut _x2 = [0u8; 32];
        unsafe {
            arsenic_generate_keypair(priv1.as_mut_ptr(), _x1.as_mut_ptr());
            arsenic_generate_keypair(priv2.as_mut_ptr(), _x2.as_mut_ptr());
        }
        let hybrid1 = unsafe { get_hybrid_pubkey(&priv1) };

        let p = default_params();
        let mut ct_buf = ArsBuffer::null();
        let rc = unsafe {
            arsenic_encrypt(b"test".as_ptr(), 4, std::ptr::null(), &p,
                            hybrid1.as_ptr(), 1, None, std::ptr::null_mut(), &mut ct_buf)
        };
        assert_eq!(rc, ARSENIC_OK);

        let mut pt_buf = ArsBuffer::null();
        let rc2 = unsafe {
            arsenic_decrypt_with_key(ct_buf.ptr, ct_buf.len, priv2.as_ptr(),
                                     None, std::ptr::null_mut(), &mut pt_buf)
        };
        assert_eq!(rc2, ARSENIC_ERR_NO_ASYM_KEY);
        unsafe { arsenic_free_buffer(&mut ct_buf); }
    }

    // ── File-based operations ─────────────────────────────────────────────────

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("arsenic_ffi_test_{name}"))
    }

    #[test]
    fn file_encrypt_decrypt_roundtrip() {
        let plain = b"file round-trip test";
        let src   = tmp_path("src.bin");
        let ct    = tmp_path("src.arsn");
        let dst   = tmp_path("dst.bin");
        std::fs::write(&src, plain).unwrap();

        let pwd = cstr("file_test_pw");
        let p   = default_params();
        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c  = CString::new(ct.to_str().unwrap()).unwrap();
        let dst_c = CString::new(dst.to_str().unwrap()).unwrap();

        let rc = unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), pwd.as_ptr(), &p,
                                 std::ptr::null(), 0, None, std::ptr::null_mut())
        };
        assert_eq!(rc, ARSENIC_OK);
        assert!(unsafe { arsenic_is_arsenic_file(ct_c.as_ptr()) } == 1);

        let rc2 = unsafe {
            arsenic_decrypt_file(ct_c.as_ptr(), dst_c.as_ptr(), pwd.as_ptr(),
                                 None, std::ptr::null_mut())
        };
        assert_eq!(rc2, ARSENIC_OK);
        assert_eq!(std::fs::read(&dst).unwrap(), plain);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
        let _ = std::fs::remove_file(&dst);
    }

    #[test]
    fn file_decrypt_wrong_password_fails() {
        let src = tmp_path("wpw_src.bin");
        let ct  = tmp_path("wpw_ct.arsn");
        let dst = tmp_path("wpw_dst.bin");
        std::fs::write(&src, b"test").unwrap();

        let _pwd  = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c  = CString::new(ct.to_str().unwrap()).unwrap();
        let dst_c = CString::new(dst.to_str().unwrap()).unwrap();
        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let right = cstr("rightpw123");
        let wrong = cstr("wrongpw456");
        let p = default_params();

        unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), right.as_ptr(), &p,
                                 std::ptr::null(), 0, None, std::ptr::null_mut())
        };
        let rc = unsafe {
            arsenic_decrypt_file(ct_c.as_ptr(), dst_c.as_ptr(), wrong.as_ptr(),
                                 None, std::ptr::null_mut())
        };
        assert_eq!(rc, ARSENIC_ERR_DECRYPT);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
        let _ = std::fs::remove_file(&dst);
    }

    #[test]
    fn file_asym_encrypt_decrypt() {
        let mut privk = [0u8; 32]; let mut _xpub = [0u8; 32];
        unsafe { arsenic_generate_keypair(privk.as_mut_ptr(), _xpub.as_mut_ptr()) };
        let hybrid_pk = unsafe { get_hybrid_pubkey(&privk) };

        let src = tmp_path("asym_src.bin");
        let ct  = tmp_path("asym_ct.arsn");
        let dst = tmp_path("asym_dst.bin");
        let plain = b"async file test";
        std::fs::write(&src, plain).unwrap();

        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c  = CString::new(ct.to_str().unwrap()).unwrap();
        let dst_c = CString::new(dst.to_str().unwrap()).unwrap();
        let p = default_params();

        let rc = unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), std::ptr::null(), &p,
                                 hybrid_pk.as_ptr(), 1, None, std::ptr::null_mut())
        };
        assert_eq!(rc, ARSENIC_OK);

        let rc2 = unsafe {
            arsenic_decrypt_file_with_key(ct_c.as_ptr(), dst_c.as_ptr(), privk.as_ptr(),
                                          None, std::ptr::null_mut())
        };
        assert_eq!(rc2, ARSENIC_OK);
        assert_eq!(std::fs::read(&dst).unwrap(), plain);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
        let _ = std::fs::remove_file(&dst);
    }

    // ── Rekey ─────────────────────────────────────────────────────────────────

    #[test]
    fn file_rekey_then_decrypt() {
        let src = tmp_path("rk_src.bin");
        let ct  = tmp_path("rk_ct.arsn");
        let dst = tmp_path("rk_dst.bin");
        let plain = b"rekey test payload";
        std::fs::write(&src, plain).unwrap();

        let src_c  = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c   = CString::new(ct.to_str().unwrap()).unwrap();
        let dst_c  = CString::new(dst.to_str().unwrap()).unwrap();
        let old_pw = cstr("old_password");
        let new_pw = cstr("new_password");
        let p = default_params();

        unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), old_pw.as_ptr(), &p,
                                 std::ptr::null(), 0, None, std::ptr::null_mut())
        };
        let rc = unsafe {
            arsenic_rekey_file(ct_c.as_ptr(), old_pw.as_ptr(), new_pw.as_ptr(),
                               None, std::ptr::null_mut())
        };
        assert_eq!(rc, ARSENIC_OK);

        // Old password no longer works.
        let mut dummy = ArsBuffer::null();
        let data = std::fs::read(&ct).unwrap();
        let rc_old = unsafe {
            arsenic_decrypt(data.as_ptr(), data.len(), old_pw.as_ptr(),
                            None, std::ptr::null_mut(), &mut dummy)
        };
        assert_eq!(rc_old, ARSENIC_ERR_DECRYPT);

        // New password works.
        let rc2 = unsafe {
            arsenic_decrypt_file(ct_c.as_ptr(), dst_c.as_ptr(), new_pw.as_ptr(),
                                 None, std::ptr::null_mut())
        };
        assert_eq!(rc2, ARSENIC_OK);
        assert_eq!(std::fs::read(&dst).unwrap(), plain);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
        let _ = std::fs::remove_file(&dst);
    }

    // ── Recipient management ──────────────────────────────────────────────────

    #[test]
    fn add_list_remove_recipient() {
        let src = tmp_path("recip_src.bin");
        let ct  = tmp_path("recip_ct.arsn");
        std::fs::write(&src, b"recipient test").unwrap();

        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c  = CString::new(ct.to_str().unwrap()).unwrap();
        let pwd   = cstr("recip_pw");
        let p = default_params();

        // Encrypt (password only, 0 recipients initially)
        unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), pwd.as_ptr(), &p,
                                 std::ptr::null(), 0, None, std::ptr::null_mut())
        };

        // List: should be 0
        let arr = unsafe { arsenic_list_recipients_file(ct_c.as_ptr()) };
        assert_eq!(arr.count, 0);
        let mut arr = arr;
        unsafe { arsenic_free_pubkey_array(&mut arr) };

        // Add a recipient (1216-byte hybrid public key)
        let mut privk = [0u8; 32]; let mut _xpub = [0u8; 32];
        unsafe { arsenic_generate_keypair(privk.as_mut_ptr(), _xpub.as_mut_ptr()) };
        let hybrid_pk = unsafe { get_hybrid_pubkey(&privk) };
        let rc = unsafe {
            arsenic_add_recipient_file(ct_c.as_ptr(), pwd.as_ptr(), hybrid_pk.as_ptr(),
                                       None, std::ptr::null_mut())
        };
        assert_eq!(rc, ARSENIC_OK);

        // List: should be 1
        let arr2 = unsafe { arsenic_list_recipients_file(ct_c.as_ptr()) };
        assert_eq!(arr2.count, 1);
        let mut arr2 = arr2;
        unsafe { arsenic_free_pubkey_array(&mut arr2) };

        // Decrypt with the new private key
        let dst = tmp_path("recip_dst.bin");
        let dst_c = CString::new(dst.to_str().unwrap()).unwrap();
        let rc2 = unsafe {
            arsenic_decrypt_file_with_key(ct_c.as_ptr(), dst_c.as_ptr(), privk.as_ptr(),
                                          None, std::ptr::null_mut())
        };
        assert_eq!(rc2, ARSENIC_OK);
        assert_eq!(std::fs::read(&dst).unwrap(), b"recipient test");

        // Remove the recipient
        let rc3 = unsafe {
            arsenic_remove_recipient_file(ct_c.as_ptr(), pwd.as_ptr(), 0,
                                          None, std::ptr::null_mut())
        };
        assert_eq!(rc3, ARSENIC_OK);

        // List: back to 0
        let arr3 = unsafe { arsenic_list_recipients_file(ct_c.as_ptr()) };
        assert_eq!(arr3.count, 0);
        let mut arr3 = arr3;
        unsafe { arsenic_free_pubkey_array(&mut arr3) };

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
        let _ = std::fs::remove_file(&dst);
    }

    #[test]
    fn find_matching_key_file_test() {
        let src = tmp_path("fmk_src.bin");
        let ct  = tmp_path("fmk_ct.arsn");
        std::fs::write(&src, b"key find test").unwrap();

        let mut privk1 = [0u8; 32]; let mut _x1 = [0u8; 32];
        let mut privk2 = [0u8; 32]; let mut _x2 = [0u8; 32];
        unsafe {
            arsenic_generate_keypair(privk1.as_mut_ptr(), _x1.as_mut_ptr());
            arsenic_generate_keypair(privk2.as_mut_ptr(), _x2.as_mut_ptr());
        }
        let hybrid1 = unsafe { get_hybrid_pubkey(&privk1) };

        let src_c = CString::new(src.to_str().unwrap()).unwrap();
        let ct_c  = CString::new(ct.to_str().unwrap()).unwrap();
        let p = default_params();

        // Encrypt for key1 only
        unsafe {
            arsenic_encrypt_file(src_c.as_ptr(), ct_c.as_ptr(), std::ptr::null(), &p,
                                 hybrid1.as_ptr(), 1, None, std::ptr::null_mut())
        };

        let path_c = ct_c.as_ptr();

        // key1 matches at index 0
        let mut keys = Vec::with_capacity(64);
        keys.extend_from_slice(&privk1);
        keys.extend_from_slice(&privk2);
        let idx = unsafe { arsenic_find_matching_key_file(path_c, keys.as_ptr(), 2) };
        assert_eq!(idx, 0, "key1 should match");

        // key2 only → no match
        let idx2 = unsafe { arsenic_find_matching_key_file(path_c, privk2.as_ptr(), 1) };
        assert_eq!(idx2, -1, "key2 should not match");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&ct);
    }

    // ── Key utilities ─────────────────────────────────────────────────────────

    #[test]
    fn keypair_generation_and_derivation() {
        let mut privk = [0u8; 32]; let mut pubk = [0u8; 32];
        unsafe { arsenic_generate_keypair(privk.as_mut_ptr(), pubk.as_mut_ptr()) };
        assert_ne!(privk, [0u8; 32]);
        assert_ne!(pubk,  [0u8; 32]);

        // Derive public key independently
        let mut derived = [0u8; 32];
        unsafe { arsenic_pubkey_from_privkey(privk.as_ptr(), derived.as_mut_ptr()) };
        assert_eq!(pubk, derived);
    }

    #[test]
    fn pubkey_encode_decode_roundtrip() {
        let mut privk = [0u8; 32]; let mut pubk = [0u8; 32];
        unsafe { arsenic_generate_keypair(privk.as_mut_ptr(), pubk.as_mut_ptr()) };

        let mut buf = [0i8; 128];
        let n = unsafe { arsenic_encode_pubkey(pubk.as_ptr(), buf.as_mut_ptr(), 128) };
        assert_eq!(n, 60); // "arsenic1" (8) + 52 bech32 chars

        let mut decoded = [0u8; 32];
        let ok = unsafe { arsenic_decode_pubkey(buf.as_ptr(), decoded.as_mut_ptr()) };
        assert_eq!(ok, 1);
        assert_eq!(pubk, decoded);
    }

    #[test]
    fn privkey_encode_decode_roundtrip() {
        let mut privk = [0u8; 32]; let mut pubk = [0u8; 32];
        unsafe { arsenic_generate_keypair(privk.as_mut_ptr(), pubk.as_mut_ptr()) };

        let mut buf = [0i8; 128];
        let n = unsafe { arsenic_encode_privkey(privk.as_ptr(), buf.as_mut_ptr(), 128) };
        assert_eq!(n, 72); // "ARSENIC-SECRET-KEY-1" (20) + 52 chars

        let mut decoded = [0u8; 32];
        let ok = unsafe { arsenic_decode_privkey(buf.as_ptr(), decoded.as_mut_ptr()) };
        assert_eq!(ok, 1);
        assert_eq!(privk, decoded);
    }

    #[test]
    fn decode_invalid_key_returns_zero() {
        let bad = cstr("not_a_key");
        let mut out = [0u8; 32];
        assert_eq!(unsafe { arsenic_decode_pubkey(bad.as_ptr(), out.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { arsenic_decode_privkey(bad.as_ptr(), out.as_mut_ptr()) }, 0);
    }

    // ── Version & misc ────────────────────────────────────────────────────────

    #[test]
    fn version_is_non_empty() {
        let ptr = arsenic_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn null_pointer_returns_err() {
        let mut out = ArsBuffer::null();
        let rc = unsafe {
            arsenic_encrypt(std::ptr::null(), 0, std::ptr::null(), std::ptr::null(),
                            std::ptr::null(), 0, None, std::ptr::null_mut(), &mut out)
        };
        assert_eq!(rc, ARSENIC_ERR_NULL_PTR);
    }

    #[test]
    fn is_arsenic_file_negative() {
        // Create a non-arsenic file
        let p = tmp_path("not_arsenic.bin");
        std::fs::write(&p, b"NOTARSENIC").unwrap();
        let c = CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { arsenic_is_arsenic_file(c.as_ptr()) }, 0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn bench_runs_and_frees() {
        let arr = arsenic_bench(1); // 1 MiB, fast
        assert_eq!(arr.count, 3);
        unsafe { arsenic_free_bench_array(arr) };
    }

    #[test]
    fn bench_best_combo() {
        let arr = arsenic_bench(1);
        let mut hdr = 0u8; let mut pld = 0u8;
        unsafe { arsenic_bench_best_combo(&arr, &mut hdr, &mut pld) };
        assert!(hdr == 0x02 || hdr == 0x03 || hdr == 0x04);
        assert_eq!(hdr, pld);
        unsafe { arsenic_free_bench_array(arr) };
    }
}
