pub mod arsenic;
mod config;
mod constants;
mod errors;
pub mod keyfmt;
pub mod keystore;
mod secret;

pub use crate::arsenic::bench::{bench_cipher_combinations, best_combination, CipherBenchResult};
pub use crate::arsenic::header::{
    MAX_ASYM_KEYSLOTS, MAX_T_COST, MAX_P_COST,
    MAX_PASSWORD_SLOTS, COMPRESS_ZSTD,
};
pub use crate::arsenic::MAX_ARGON2_RAM_KB;
pub use crate::arsenic::{
    ArsenicParams, ArsenicStrength, CipherId, EnvelopeMetadata,
    HybridKeyslot, HybridKeyslot1024, HybridRecipient, HybridPrivKey, KemLevel,
    PasswordSlot,
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic,
    encrypt_arsenic_to_writer,
    decrypt_block_at, decrypt_block_at_with_key,
    find_decrypting_key, find_slot_for_privkey, list_recipients, rekey_arsenic,
    armor, dearmor,
    BLOCK_SIZE_4MB, MIN_HEADER_TOTAL_SIZE, PASSWORD_SLOT_LEN,
};
pub use crate::arsenic::header::SenderInfo;

/// Armor encoding reveals the exact ciphertext length, which leaks a lower
/// bound on the plaintext size.  For size-sensitive data, transport the raw
/// `.arsn` binary instead.
pub const ARMOR_LEAKS_SIZE: &str =
    "ASCII armor reveals ciphertext length — leaks plaintext size lower bound.";

/// Enabling zstd compression leaks plaintext entropy via ciphertext size.
///
/// An observer can infer characteristics of the plaintext (language, structure,
/// partial content) from the compression ratio.  This is analogous to the
/// CRIME/BREACH attacks against TLS compression.  Only enable compression when
/// plaintext size confidentiality is not required.
pub const COMPRESSION_LEAKS_SIZE: &str =
    "zstd compression leaks plaintext entropy via ciphertext size — \
     disable for size-sensitive data.";
pub use crate::config::{Direction, Ui};
pub use crate::keyfmt::{
    decode_mlkem_pubkey, decode_privkey, decode_pubkey,
    encode_mlkem_pubkey, encode_privkey, encode_pubkey,
    encode_mlkem_seed, decode_mlkem_seed,
};
pub use crate::constants::*;
pub use crate::errors::CoreErr;
pub use crate::secret::*;

use std::fs::{remove_file, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Instant;


/// Read the sender identity stored in clear in the header.
///
/// No password or private key is required, so the result is **not
/// authenticated** on its own: the header MAC that covers it is only checked
/// when the file is decrypted. Read it after a successful decryption.
///
/// Returns `None` if the file has no sender info, cannot be opened, or the
/// header is malformed.
pub fn arsenic_read_sender_info(path: &std::path::Path) -> Option<SenderInfo> {
    let mut f = File::open(path).ok()?;
    arsenic::read_header(&mut f).ok()?.sender
}

/// True if `key` is a well-formed ML-KEM-768 public key.
pub fn mlkem_pubkey_is_valid(key: &[u8; 1184]) -> bool {
    arsenic::hybrid_kem::is_valid_ek_768(key)
}

pub const fn get_version() -> &'static str {
    APP_VERSION
}

/// Return 32 cryptographically random bytes drawn directly from the OS CSPRNG.
///
/// # Panics
/// If the operating system cannot provide randomness — there is no safe way
/// to continue without it.
#[allow(clippy::expect_used)]
pub fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

/// Derive the ML-KEM-768 encapsulation key from a 64-byte ML-KEM seed.
pub fn hybrid_encapsulation_key(mlkem_seed: &[u8; 64]) -> [u8; 1184] {
    arsenic::hybrid_kem::encapsulation_key_768(mlkem_seed)
}

/// Build a `HybridRecipient` from a `KeyEntry` (uses independently-seeded keys).
pub fn hybrid_recipient_from_key_entry(entry: &keystore::KeyEntry) -> HybridRecipient {
    entry.as_recipient()
}

/// Build a `HybridRecipient` from an X25519 private key using BLAKE3-derived ML-KEM seed.
///
/// Legacy function for contexts where only the 32-byte X25519 key is available.
pub fn hybrid_recipient_from_privkey(x25519_sk: &[u8; 32]) -> HybridRecipient {
    let mlkem_seed = arsenic::hybrid_kem::seed_from_x25519(x25519_sk);
    HybridRecipient::new(
        pubkey_from_privkey(x25519_sk),
        arsenic::hybrid_kem::encapsulation_key_768(&mlkem_seed),
    )
}

/// Derive a 64-byte ML-KEM seed from a 32-byte X25519 key (legacy / backward compat).
pub fn mlkem_seed_from_x25519(x25519_sk: &[u8; 32]) -> [u8; 64] {
    arsenic::hybrid_kem::seed_from_x25519(x25519_sk)
}

/// Derive the ML-KEM-768 encapsulation key from a 64-byte seed.
pub fn mlkem_encapsulation_key_768(mlkem_seed: &[u8; 64]) -> [u8; 1184] {
    arsenic::hybrid_kem::encapsulation_key_768(mlkem_seed)
}

/// Derive the X25519 public key from a private key.
pub fn pubkey_from_privkey(privkey: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    *PublicKey::from(&StaticSecret::from(*privkey)).as_bytes()
}

/// Generate a fresh X25519 keypair.  Returns `(private_key_32, public_key_32)`.
///
/// The private key is cryptographically random (32 bytes).
/// The caller is responsible for storing and zeroizing it appropriately.
///
/// # Panics
/// If the operating system cannot provide randomness.
#[allow(clippy::expect_used)]
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut privkey_bytes = [0u8; 32];
    getrandom::fill(&mut privkey_bytes).expect("OS random number generator unavailable");
    let secret = StaticSecret::from(privkey_bytes);
    let pubkey = PublicKey::from(&secret);
    (privkey_bytes, *pubkey.as_bytes())
}

/// Read the Argon2id parameters stored in an Arsenic file header.
/// Returns `None` if the file cannot be read or is not a valid Arsenic file.
pub fn arsenic_read_params(path: &std::path::Path) -> Option<ArsenicParams> {
    // all KDF params are within the first PUB_HEADER_LEN bytes
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; arsenic::header::PUB_HEADER_LEN];
    f.read_exact(&mut buf).ok()?;
    if buf[0..4] != arsenic::header::MAGIC {
        return None;
    }
    if buf[4..6] != arsenic::header::VERSION {
        return None;
    }
    // offsets: t_cost at 29..33, m_cost at 33..37, p_cost at 37..41
    // (see the layout at the top of `arsenic/header.rs`)
    Some(ArsenicParams {
        t_cost: u32::from_le_bytes(buf[29..33].try_into().ok()?),
        m_cost: u32::from_le_bytes(buf[33..37].try_into().ok()?),
        p_cost: u32::from_le_bytes(buf[37..41].try_into().ok()?),
        hdr_cipher: arsenic::CipherId::from_byte(buf[7]).ok()?,
        pld_cipher: arsenic::CipherId::from_byte(buf[8]).ok()?,
        metadata: EnvelopeMetadata::default(),
        recipients: vec![],
        kem_level: arsenic::KemLevel::L768,
        sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
        compress: None,
    })
}

/// Probe a file to find which keypair (if any) can decrypt it.
///
/// Returns `Some(i)` if `keys[i]` matches one of the file's asymmetric keyslots.
pub fn arsenic_find_matching_key(path: &std::path::Path, keys: &[keystore::KeyEntry]) -> Option<usize> {
    let mut f = File::open(path).ok()?;
    let hybrid_keys: Vec<HybridPrivKey<'_>> = keys
        .iter()
        .map(|k| HybridPrivKey { x25519_sk: &k.private_key, mlkem_seed: &k.mlkem_seed })
        .collect();
    arsenic::find_decrypting_key(&mut f, &hybrid_keys).ok().flatten()
}

/// Find which **keyslot index** can be opened with this keypair.
/// Returns the slot position to pass to `arsenic_remove_recipient`.
pub fn arsenic_find_slot_for_key(path: &std::path::Path, key: &keystore::KeyEntry) -> Option<usize> {
    let mut f = File::open(path).ok()?;
    arsenic::find_slot_for_privkey(&mut f, &key.private_key, &key.mlkem_seed).ok().flatten()
}

/// Legacy variant for callers that only have a 32-byte X25519 key (FFI / old code).
/// Derives the ML-KEM seed via BLAKE3 for backward compat.
pub fn arsenic_find_slot_for_privkey_legacy(path: &std::path::Path, x25519_sk: &[u8; 32]) -> Option<usize> {
    let mlkem_seed = arsenic::hybrid_kem::seed_from_x25519(x25519_sk);
    let mut f = File::open(path).ok()?;
    arsenic::find_slot_for_privkey(&mut f, x25519_sk, &mlkem_seed).ok().flatten()
}

/// Path of the header backup kept next to `path` while its header is rewritten.
fn header_backup_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

/// If a previous in-place header rewrite of `path` was interrupted, put the
/// saved header back. Returns `true` if a backup was restored.
///
/// A leftover backup means the rewrite did not reach its end, so the header
/// on disk may be the old one, the new one, or a mix of both. The backup is
/// always a complete, consistent header (the payload and the file key never
/// change), so it is restored unconditionally.
fn restore_interrupted_header(path: &std::path::Path) -> Result<bool, CoreErr> {
    let bak_path = header_backup_path(path);
    if !bak_path.exists() {
        return Ok(false);
    }
    let backup = std::fs::read(&bak_path)?;
    // Only a backup that is itself a complete header is restored; anything
    // else is a leftover that cannot help and is simply discarded.
    let valid = arsenic::header::Header::parse(&backup).is_ok();
    if valid {
        let mut f = OpenOptions::new().write(true).open(path)?;
        f.write_all(&backup)?;
        f.sync_all()?;
    }
    remove_file(&bak_path)?;
    Ok(valid)
}

/// Change one password of an Arsenic file without touching the payload.
///
/// The slot of `old_password` is replaced by a slot for `new_password`; other
/// passwords and recipients keep working. The file key does not change:
/// someone who knew the old password and kept a copy of the old file can
/// still decrypt that copy.
///
/// The header is rewritten in place. The current header is first saved to
/// `<path>.bak` and synced; the backup is removed on success. If a previous
/// change was interrupted, the saved header is restored and an error asks the
/// caller to retry (with the password that was valid before that attempt).
pub fn arsenic_rekey(
    path: &std::path::Path,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    if restore_interrupted_header(path)? {
        return Err(CoreErr::DecryptFail(
            "a previous password change was interrupted; the previous header has been restored. \
             Please retry."
                .into(),
        ));
    }

    // ── Back up the current header ────────────────────────────────────────
    let bak_path = header_backup_path(path);
    {
        let current = arsenic::read_header(&mut File::open(path)?)?.to_bytes();
        let mut bak = File::create(&bak_path)?;
        bak.write_all(&current)?;
        bak.sync_all()?;
        // On POSIX filesystems the directory entry is separate metadata:
        // syncing the file alone does not guarantee the backup can be found
        // by name after a power failure. Windows journals directory entries
        // and cannot open a directory this way.
        #[cfg(unix)]
        if let Some(parent) = bak_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
    }

    let result = (|| {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        arsenic::rekey_arsenic(&mut f, old_password, new_password, ui)?;
        f.sync_all()?;
        Ok(())
    })();

    // On success the new header is on disk. On failure before the write the
    // file is untouched; on failure during the write the backup stays and is
    // restored by the next call.
    if result.is_ok() || !matches!(result, Err(CoreErr::IOError(_))) {
        let _ = remove_file(&bak_path);
    }
    result
}

/// Add a hybrid recipient to an existing Arsenic file.
///
/// Authenticates with `password` (any password of the file) and rewrites the
/// file with the larger header; the payload is copied unchanged. The new
/// keyslot follows the file's ML-KEM level — see
/// [`arsenic_add_recipient_with_level`] to choose it.
pub fn arsenic_add_recipient(
    path: &std::path::Path,
    password: &Secret<String>,
    recipient: &arsenic::HybridRecipient,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    arsenic_add_recipient_with_level(path, password, recipient, None, ui)
}

/// Like [`arsenic_add_recipient`], with an explicit ML-KEM level for the new
/// keyslot (`None` = follow the file).
pub fn arsenic_add_recipient_with_level(
    path: &std::path::Path,
    password: &Secret<String>,
    recipient: &arsenic::HybridRecipient,
    level: Option<KemLevel>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    ui.output(0);
    let (new_header, old_header_size) = {
        let mut f = File::open(path)?;
        arsenic::build_header_with_added_recipient(&mut f, password, recipient, level)?
    };
    rewrite_file_with_new_header(path, &new_header, old_header_size)?;
    ui.output(100);
    Ok(())
}

/// Remove the asymmetric keyslot at position `index` from an Arsenic file.
///
/// `index` uses the numbering of [`arsenic_list_recipients`]: ML-KEM-768
/// slots first, then ML-KEM-1024 slots. Requires a password of the file.
/// Rewrites the file with the smaller header; the payload is copied unchanged.
pub fn arsenic_remove_recipient(
    path: &std::path::Path,
    password: &Secret<String>,
    index: usize,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    ui.output(0);

    let (new_header, old_header_size) = {
        let mut f = File::open(path)?;
        arsenic::build_header_with_removed_recipient(&mut f, password, index)?
    };

    rewrite_file_with_new_header(path, &new_header, old_header_size)?;
    ui.output(100);
    Ok(())
}

/// Return the ephemeral public keys of all asymmetric keyslots in the file
/// (ML-KEM-768 slots first, then ML-KEM-1024 slots).
///
/// These identify slots (by position) but are NOT the recipients' own public keys.
pub fn arsenic_list_recipients(path: &std::path::Path) -> Result<Vec<[u8; 32]>, CoreErr> {
    let mut f = File::open(path)?;
    arsenic::list_recipients(&mut f)
}

/// Rewrite `path` replacing the first `old_header_size` bytes with `new_header`,
/// copying the rest of the file unchanged. Uses a sibling temporary file and
/// an atomic rename, so the original is intact until the new file is complete.
fn rewrite_file_with_new_header(
    path: &std::path::Path,
    new_header: &[u8],
    old_header_size: usize,
) -> Result<(), CoreErr> {
    // A name next to the target, so the rename stays on one filesystem.
    let tmp_path = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{:016x}.tmp", u64::from_le_bytes(random_bytes_32()[..8].try_into().unwrap_or_default())));
        path.with_file_name(name)
    };

    let result = (|| -> Result<(), CoreErr> {
        let mut tmp = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        tmp.write_all(new_header)?;
        let mut src = File::open(path)?;
        src.seek(SeekFrom::Start(old_header_size as u64))?;
        std::io::copy(&mut src, &mut tmp)?;
        tmp.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = remove_file(&tmp_path);
        return result;
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = remove_file(&tmp_path);
        return Err(CoreErr::IOError(e));
    }
    Ok(())
}

/// Decrypt an Arsenic file using a `KeyEntry` (X25519 + independent ML-KEM seed).
// Public API (also used by the FFI crate): the progress handler is owned.
#[allow(clippy::needless_pass_by_value)]
pub fn arsenic_main_routine_with_key(
    filename: Option<&str>,
    out_file: Option<&str>,
    key: &keystore::KeyEntry,
    ui: Box<dyn Ui>,
) -> Result<f64, CoreErr> {
    let in_path = filename.ok_or_else(|| {
        CoreErr::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no input filename provided",
        ))
    })?;
    let out_path = out_file.ok_or_else(|| {
        CoreErr::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no output filename provided",
        ))
    })?;

    let mut in_file = File::open(in_path)?;
    let filesize = in_file.metadata()?.len();
    let start = Instant::now();
    let privkey = Secret::new(key.private_key);

    let mut out = File::create(out_path)?;
    if let Err(e) = arsenic::decrypt_arsenic_with_key(
        &mut in_file, &mut out, &privkey, &key.mlkem_seed, &*ui, filesize,
    ) {
        let _ = remove_file(out_path);
        return Err(e);
    }

    Ok(start.elapsed().as_secs_f64())
}

/// Detect whether a file starts with the Arsenic magic ("ARSN").
pub fn is_arsenic_file(path: &std::path::Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .is_ok_and(|()| magic == arsenic::header::MAGIC)
}

/// Encrypt or decrypt a file in Arsenic format.
// Public API (also used by the FFI crate): the progress handler is owned.
#[allow(clippy::needless_pass_by_value)]
pub fn arsenic_main_routine(
    direction: &Direction,
    filename: Option<&str>,
    out_file: Option<&str>,
    password: &Secret<String>,
    ui: Box<dyn Ui>,
    params: Option<ArsenicParams>,
) -> Result<f64, CoreErr> {
    let in_path = filename.ok_or_else(|| {
        CoreErr::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no input filename provided",
        ))
    })?;
    let out_path = out_file.ok_or_else(|| {
        CoreErr::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no output filename provided",
        ))
    })?;

    let mut in_file = File::open(in_path)?;
    let filesize = in_file.metadata()?.len();

    let start = Instant::now();

    match direction {
        Direction::Encrypt => {
            let mut out = File::create(out_path)?;
            let p = params.unwrap_or_default();
            if let Err(e) =
                arsenic::encrypt_arsenic(&mut in_file, &mut out, password, &*ui, filesize, &p)
            {
                let _ = remove_file(out_path);
                return Err(e);
            }
        }
        Direction::Decrypt => {
            let mut out = File::create(out_path)?;
            if let Err(e) =
                arsenic::decrypt_arsenic(&mut in_file, &mut out, password, &*ui, filesize)
            {
                let _ = remove_file(out_path);
                return Err(e);
            }
        }
    }

    Ok(start.elapsed().as_secs_f64())
}

// ── Password slot management ──────────────────────────────────────────────────

/// Add a password to an Arsenic file.
///
/// `existing_password` may be any password of the file. Afterwards the file
/// opens with either one. At most [`MAX_PASSWORD_SLOTS`] passwords per file.
/// All of them share the file's Argon2id salt and parameters, so a wrong
/// password costs one Argon2id run whatever their number.
pub fn arsenic_add_passphrase(
    path: &std::path::Path,
    existing_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    ui.output(0);
    let (new_header, old_header_size) = {
        let mut f = File::open(path)?;
        arsenic::build_header_with_added_passphrase(&mut f, existing_password, new_password)?
    };
    rewrite_file_with_new_header(path, &new_header, old_header_size)?;
    ui.output(100);
    Ok(())
}

/// Remove a password from an Arsenic file.
///
/// `password` authenticates the operation and may be any password of the
/// file, including `password_to_remove` itself. The last key slot of a file
/// (password or recipient) cannot be removed.
pub fn arsenic_remove_passphrase(
    path: &std::path::Path,
    password: &Secret<String>,
    password_to_remove: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    ui.output(0);
    let (new_header, old_header_size) = {
        let mut f = File::open(path)?;
        arsenic::build_header_with_removed_passphrase(&mut f, password, password_to_remove)?
    };
    rewrite_file_with_new_header(path, &new_header, old_header_size)?;
    ui.output(100);
    Ok(())
}

/// Return the number of password slots of the file (0 = keypairs only).
///
/// Reads the header without any key; the count is visible to anyone.
pub fn arsenic_list_passphrases(path: &std::path::Path) -> Result<usize, CoreErr> {
    let mut f = File::open(path)?;
    Ok(arsenic::read_header(&mut f)?.password_slots.len())
}
