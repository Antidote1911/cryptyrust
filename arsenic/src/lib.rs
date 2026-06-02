pub mod arsenic;
mod config;
mod constants;
mod errors;
pub mod keyfmt;
pub mod keystore;
mod secret;

pub use crate::arsenic::bench::{bench_cipher_combinations, best_combination, CipherBenchResult};
pub use crate::arsenic::header::{MAX_ASYM_KEYSLOTS, MAX_T_COST, MAX_P_COST};
pub use crate::arsenic::MAX_ARGON2_RAM_KB;
pub use crate::arsenic::{
    ArsenicParams, ArsenicStrength, CipherId, EnvelopeMetadata,
    HybridKeyslot, HybridKeyslot1024, HybridRecipient, HybridPrivKey, KemLevel,
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic,
    find_decrypting_key, find_slot_for_privkey, list_recipients, rekey_arsenic,
    BLOCK_SIZE_4MB, MIN_HEADER_TOTAL_SIZE,
};
pub use crate::arsenic::header::SenderInfo;
pub use crate::config::{Direction, Ui};
pub use crate::keyfmt::{
    decode_mlkem_pubkey, decode_privkey, decode_pubkey,
    encode_mlkem_pubkey, encode_privkey, encode_pubkey,
    encode_mlkem_seed, decode_mlkem_seed,
};
pub use crate::constants::*;
pub use crate::errors::CoreErr;
pub use crate::secret::*;
pub use crate::keyfmt::{encode_mldsa_vk, decode_mldsa_vk};

use std::fs::{remove_file, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Instant;

/// Result of checking a file's ML-DSA-65 signature against the contact trust store.
#[derive(Debug, Clone)]
pub enum SignatureStatus {
    /// The file contains no ML-DSA-65 signature.
    NotSigned,
    /// Signature is cryptographically valid and the verifying key matches a trusted contact.
    SignedByKnown(String),
    /// Signature is cryptographically valid but the verifying key is not in the trust store.
    SignedByUnknown,
    /// A signature region is present but the signature is cryptographically invalid.
    Invalid,
}

/// Compute a short fingerprint of a verifying key for out-of-band verification.
///
/// Returns the first 8 bytes of BLAKE3(vk) as colon-separated hex pairs,
/// e.g. `"ab:12:cd:34:ef:56:78:90"`. The fingerprint is stable across sessions
/// and can be read aloud or compared via Signal to confirm a first contact.
pub fn vk_fingerprint(vk: &[u8; 1952]) -> String {
    let hash = blake3::hash(vk);
    hash.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Cryptographically verify the ML-DSA-65 signature of a file and classify it
/// against the contact trust store.
///
/// Unlike a simple VK lookup, this function **verifies the signature
/// mathematically** — it reads the header, reconstructs the signed message
/// (`pre_mac || sender_bytes`), and confirms the signature is valid before
/// checking the trust store. Returns `Invalid` if the signature does not verify.
///
/// Also checks `own_keys` first so self-signed files are labelled "(you)".
///
/// Returns `(status, fingerprint)` where `fingerprint` is `Some(hex_string)`
/// when a signature is present (valid or not), useful for out-of-band TOFU
/// verification when `status == SignedByUnknown`.
pub fn arsenic_check_signature(
    path: &std::path::Path,
    own_keys: &[keystore::KeyEntry],
    contacts: &[keystore::ContactEntry],
) -> (SignatureStatus, Option<String>) {
    use arsenic::header::{parse_header_bytes, parse_envelope, build_signed_message, MIN_HEADER_TOTAL_SIZE};
    use crate::arsenic::MAX_HEADER_TOTAL_SIZE;
    use ml_dsa::{MlDsa65, Verifier};

    // ── Read header ───────────────────────────────────────────────────────────
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return (SignatureStatus::NotSigned, None),
    };
    let mut prefix = [0u8; 13];
    if f.read_exact(&mut prefix).is_err() {
        return (SignatureStatus::NotSigned, None);
    }
    let header_total_size =
        u32::from_le_bytes([prefix[9], prefix[10], prefix[11], prefix[12]]) as usize;
    if header_total_size < MIN_HEADER_TOTAL_SIZE
        || header_total_size > MAX_HEADER_TOTAL_SIZE as usize
    {
        return (SignatureStatus::NotSigned, None);
    }
    let mut header_buf = vec![0u8; header_total_size];
    header_buf[..13].copy_from_slice(&prefix);
    if f.read_exact(&mut header_buf[13..]).is_err() {
        return (SignatureStatus::NotSigned, None);
    }

    let (_, pre_mac_bytes, _, enc_env_region) = match parse_header_bytes(&header_buf) {
        Ok(x) => x,
        Err(_) => return (SignatureStatus::NotSigned, None),
    };
    let envelope = match parse_envelope(&enc_env_region) {
        Ok(e) => e,
        Err(_) => return (SignatureStatus::NotSigned, None),
    };

    let mldsa = match envelope.mldsa_sig {
        Some(ref s) => s,
        None => return (SignatureStatus::NotSigned, None),
    };

    // ── Fingerprint (computed regardless of validity) ─────────────────────────
    let fingerprint = Some(vk_fingerprint(&mldsa.verifying_key));

    // ── Cryptographic verification ────────────────────────────────────────────
    let vk_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(mldsa.verifying_key.as_slice()) {
        Ok(x) => x,
        Err(_) => return (SignatureStatus::Invalid, fingerprint),
    };
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let sig = match ml_dsa::Signature::<MlDsa65>::try_from(mldsa.signature.as_slice()) {
        Ok(x) => x,
        Err(_) => return (SignatureStatus::Invalid, fingerprint),
    };
    let signed_msg = build_signed_message(&pre_mac_bytes, &envelope.protected_meta, envelope.sender.as_ref());
    if vk.verify(&signed_msg, &sig).is_err() {
        return (SignatureStatus::Invalid, fingerprint);
    }

    // ── Trust store lookup ────────────────────────────────────────────────────
    let vk_bytes = mldsa.verifying_key.as_slice();
    for key in own_keys {
        if let Some(ref own_vk) = key.signing_verifying_key {
            if own_vk.as_slice() == vk_bytes {
                return (SignatureStatus::SignedByKnown(format!("{} (vous)", key.name)), fingerprint);
            }
        }
    }
    for c in contacts {
        if let Some(ref trusted_vk) = c.signing_verifying_key {
            if trusted_vk.as_slice() == vk_bytes {
                return (SignatureStatus::SignedByKnown(c.name.clone()), fingerprint);
            }
        }
    }
    (SignatureStatus::SignedByUnknown, fingerprint)
}

/// Read sender identity embedded in the **public** (unencrypted) header region.
///
/// No password or private key is required — the sender region is intentionally
/// stored in plaintext so the recipient can identify who sent the file before
/// decrypting, and can automatically add the sender to their contact list.
///
/// Returns `None` if the file has no sender info, cannot be opened, or the
/// header is malformed.
pub fn arsenic_read_sender_info(path: &std::path::Path) -> Option<SenderInfo> {
    use arsenic::header::{parse_header_bytes, parse_envelope, MIN_HEADER_TOTAL_SIZE};
    use crate::arsenic::MAX_HEADER_TOTAL_SIZE;

    let mut f = File::open(path).ok()?;
    let mut prefix = [0u8; 13];
    f.read_exact(&mut prefix).ok()?;
    let header_total_size =
        u32::from_le_bytes([prefix[9], prefix[10], prefix[11], prefix[12]]) as usize;
    if header_total_size < MIN_HEADER_TOTAL_SIZE
        || header_total_size > MAX_HEADER_TOTAL_SIZE as usize
    {
        return None;
    }
    let mut header_buf = vec![0u8; header_total_size];
    header_buf[..13].copy_from_slice(&prefix);
    f.read_exact(&mut header_buf[13..]).ok()?;

    let (_, _, _, enc_env_region) = parse_header_bytes(&header_buf).ok()?;
    let envelope = parse_envelope(&enc_env_region).ok()?;
    envelope.sender
}

/// Read the ML-DSA-65 verifying key from a file's header without decrypting.
///
/// Returns `None` if the file has no signature, cannot be opened, or the
/// header is malformed.
pub fn arsenic_read_verifying_key(path: &std::path::Path) -> Option<Box<[u8; 1952]>> {
    use arsenic::header::{parse_header_bytes, parse_envelope, MIN_HEADER_TOTAL_SIZE};
    use crate::arsenic::MAX_HEADER_TOTAL_SIZE;

    let mut f = File::open(path).ok()?;
    let mut prefix = [0u8; 13];
    f.read_exact(&mut prefix).ok()?;
    let header_total_size =
        u32::from_le_bytes([prefix[9], prefix[10], prefix[11], prefix[12]]) as usize;
    if header_total_size < MIN_HEADER_TOTAL_SIZE
        || header_total_size > MAX_HEADER_TOTAL_SIZE as usize
    {
        return None;
    }
    let mut header_buf = vec![0u8; header_total_size];
    header_buf[..13].copy_from_slice(&prefix);
    f.read_exact(&mut header_buf[13..]).ok()?;

    let (_, _, _, enc_env_region) = parse_header_bytes(&header_buf).ok()?;
    let envelope = parse_envelope(&enc_env_region).ok()?;
    envelope.mldsa_sig.map(|sig| sig.verifying_key)
}

pub const fn get_version() -> &'static str {
    APP_VERSION
}

/// Return 32 cryptographically random bytes drawn directly from the OS CSPRNG.
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
    Some(ArsenicParams {
        t_cost: u32::from_le_bytes(buf[29..33].try_into().ok()?),
        m_cost: u32::from_le_bytes(buf[33..37].try_into().ok()?),
        p_cost: u32::from_le_bytes(buf[37..41].try_into().ok()?),
        hdr_cipher: arsenic::CipherId::from_byte(buf[7]).ok()?,
        pld_cipher: arsenic::CipherId::from_byte(buf[8]).ok()?,
        metadata: EnvelopeMetadata::default(),
        recipients: vec![],
        kem_level: arsenic::KemLevel::L768,
        signing_key: None,
        sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
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

/// Change the symmetric password of an Arsenic file without decrypting the payload.
///
/// A backup of the current header is written to `<path>.bak` and flushed before
/// the in-place write.  On success the backup is removed.  On crash the backup
/// allows restoring the original header.
pub fn arsenic_rekey(
    path: &std::path::Path,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    let bak_path = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".bak");
        path.with_file_name(name)
    };

    // ── Detect interrupted previous rekey ─────────────────────────────────
    if bak_path.exists() {
        let magic_intact = {
            let mut magic = [0u8; 4];
            File::open(path)
                .and_then(|mut f| f.read_exact(&mut magic))
                .is_ok_and(|_| magic == arsenic::header::MAGIC)
        };

        if !magic_intact {
            let backup = std::fs::read(&bak_path)?;
            if backup.len() >= arsenic::header::MIN_HEADER_TOTAL_SIZE {
                let mut f = OpenOptions::new().write(true).open(path)?;
                f.write_all(&backup)?;
                f.sync_all()?;
            }
            let _ = remove_file(&bak_path);
            return Err(CoreErr::DecryptFail(
                "A previous rekey was interrupted and the header was corrupted. \
                 It has been restored from the backup. Please retry."
                    .into(),
            ));
        }
    }

    // ── Read current header (u32 header_total_size) and back it up ────────
    {
        let header_total_size = {
            let mut size_buf = [0u8; 13]; // header_total_size at offset 9 (u32 LE)
            File::open(path)?.read_exact(&mut size_buf)?;
            u32::from_le_bytes([size_buf[9], size_buf[10], size_buf[11], size_buf[12]]) as usize
        };
        if header_total_size < arsenic::header::MIN_HEADER_TOTAL_SIZE
            || header_total_size > arsenic::MAX_HEADER_TOTAL_SIZE as usize
        {
            return Err(CoreErr::DecryptFail(
                "Invalid header_total_size in file".into(),
            ));
        }
        let mut current_hdr = vec![0u8; header_total_size];
        File::open(path)?.read_exact(&mut current_hdr)?;
        let mut bak = File::create(&bak_path)?;
        bak.write_all(&current_hdr)?;
        bak.sync_all()?;
        // On POSIX filesystems (ext4, btrfs, ZFS) the directory entry is
        // separate metadata from the inode; fsync on the file alone does NOT
        // guarantee the filename→inode mapping is on disk.  Fsyncing the
        // parent directory ensures the .bak is reachable by name even after
        // a power failure mid-rewrite.
        // On Windows, NTFS journals directory entries automatically and
        // File::open() on a directory returns "Access is denied", so we
        // skip this step on non-Unix platforms.
        #[cfg(unix)]
        if let Some(parent) = bak_path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }

    let result = {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        arsenic::rekey_arsenic(&mut f, old_password, new_password, ui)
    };

    if result.is_ok() {
        let _ = remove_file(&bak_path);
    }

    result
}

/// Add a hybrid (X25519 + ML-KEM-768) recipient to an existing Arsenic file.
///
/// Authenticates with `password`, derives the DEK from the symmetric keyslot,
/// generates a fresh hybrid keyslot for `recipient`, and rewrites
/// the file with the expanded header.  The payload is streamed unchanged.
pub fn arsenic_add_recipient(
    path: &std::path::Path,
    password: &Secret<String>,
    recipient: &arsenic::HybridRecipient,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    ui.output(0);
    let hdr_cipher = arsenic_read_params(path)
        .map(|p| p.hdr_cipher)
        .unwrap_or(arsenic::CipherId::DeoxysII256);

    let (new_header, old_header_size) = {
        let mut f = File::open(path)?;
        arsenic::build_header_with_added_recipient(&mut f, password, hdr_cipher, recipient)?
    };

    rewrite_file_with_new_header(path, &new_header, old_header_size)?;
    ui.output(100);
    Ok(())
}

/// Remove the asymmetric keyslot at position `index` from an Arsenic file.
///
/// Requires the symmetric `password` to authenticate the operation.  Rewrites
/// the file with the shrunken header; the payload is streamed unchanged.
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

/// Return the ephemeral public keys of all asymmetric keyslots in the file.
///
/// These identify slots (by position) but are NOT the recipients' own public keys.
pub fn arsenic_list_recipients(path: &std::path::Path) -> Result<Vec<[u8; 32]>, CoreErr> {
    let mut f = File::open(path)?;
    arsenic::list_recipients(&mut f)
}

/// Rewrite `path` replacing the first `old_header_size` bytes with `new_header`,
/// streaming the rest of the file unchanged.  Uses a temp file + atomic rename.
fn rewrite_file_with_new_header(
    path: &std::path::Path,
    new_header: &[u8],
    old_header_size: usize,
) -> Result<(), CoreErr> {
    let tmp_path = path.with_extension("arsn.tmp");

    let result = (|| -> Result<(), CoreErr> {
        let mut tmp = File::create(&tmp_path)?;
        tmp.write_all(new_header)?;

        let mut src = File::open(path)?;
        src.seek(SeekFrom::Start(old_header_size as u64))?;

        let mut chunk = vec![0u8; 4 * 1024 * 1024];
        loop {
            let n = src.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            tmp.write_all(&chunk[..n])?;
        }
        tmp.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = remove_file(&tmp_path);
        return result;
    }

    std::fs::rename(&tmp_path, path).map_err(CoreErr::IOError)
}

/// Decrypt an Arsenic file using a `KeyEntry` (X25519 + independent ML-KEM seed).
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
        .is_ok_and(|_| magic == arsenic::header::MAGIC)
}

/// Encrypt or decrypt a file in Arsenic format.
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
