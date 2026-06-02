//! Shared X25519 keystore — `{config}/cryptyrust/keys/*.key`.
//!
//! Used by the GUI, CLI, and keygen to store and load keypairs and contacts
//! from the same location on all platforms.

use crate::{
    decode_mlkem_pubkey, decode_privkey, decode_pubkey,
    encode_mlkem_pubkey, encode_privkey, encode_pubkey,
    generate_x25519_keypair, pubkey_from_privkey,
};
use crate::arsenic::hybrid_kem;
use crate::keyfmt::{encode_mlkem_seed, decode_mlkem_seed, encode_mldsa_vk, decode_mldsa_vk,
    bech32_encode_upper, bech32_decode_lower};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSignKey, KeyExport, Keypair, Seed as MlDsaSeed};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A complete identity stored in a `.key` file: encryption keypair + ML-DSA-65 signing key.
///
/// All three components (X25519, ML-KEM, ML-DSA) are generated with independent
/// entropy from the OS CSPRNG in a single `generate()` call.
///
/// Legacy files without `# sign-seed:` have `signing_seed = None`; they can still
/// encrypt/decrypt but cannot sign.
#[derive(Clone)]
pub struct KeyEntry {
    pub name: String,
    /// X25519 private key (32 bytes).
    pub private_key: [u8; 32],
    /// ML-KEM-768 seed: `d[32] || z[32]` — independent of `private_key`.
    pub mlkem_seed: [u8; 64],
    /// X25519 public key.
    pub public_key: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes, derived from mlkem_seed).
    pub mlkem_public_key: Box<[u8; 1184]>,
    /// ML-DSA-65 signing seed (32 bytes), zeroized on drop — `None` for legacy key files.
    pub signing_seed: Option<Zeroizing<[u8; 32]>>,
    /// ML-DSA-65 verifying key (1952 bytes) — `None` for legacy key files.
    pub signing_verifying_key: Option<Box<[u8; 1952]>>,
    /// Path of the `.key` file on disk (`None` before first save).
    pub file_path: Option<PathBuf>,
}

impl KeyEntry {
    pub fn generate(name: String) -> Self {
        use crate::random_bytes_32;
        let (private_key, public_key) = generate_x25519_keypair();
        // Independent entropy for ML-KEM.
        let mut mlkem_seed = [0u8; 64];
        mlkem_seed[..32].copy_from_slice(&random_bytes_32());
        mlkem_seed[32..].copy_from_slice(&random_bytes_32());
        let mlkem_public_key = Box::new(hybrid_kem::encapsulation_key_768(&mlkem_seed));
        // Independent entropy for ML-DSA-65 signing.
        let signing_seed = random_bytes_32();
        let sign_seed_arr: ml_dsa::Seed = signing_seed.into();
        let sign_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&sign_seed_arr);
        let sign_vk = <ml_dsa::SigningKey<ml_dsa::MlDsa65> as ml_dsa::Keypair>::verifying_key(&sign_sk);
        let vk_enc = <ml_dsa::VerifyingKey<ml_dsa::MlDsa65> as ml_dsa::KeyExport>::to_bytes(&sign_vk);
        let mut vk_arr = [0u8; 1952];
        vk_arr.copy_from_slice(vk_enc.as_slice());
        Self {
            name, private_key, mlkem_seed, public_key, mlkem_public_key,
            signing_seed: Some(Zeroizing::new(signing_seed)),
            signing_verifying_key: Some(Box::new(vk_arr)),
            file_path: None,
        }
    }

    /// Build a `HybridRecipient` including both ML-KEM-768 and ML-KEM-1024 keys.
    pub fn as_recipient(&self) -> crate::arsenic::HybridRecipient {
        let mlkem_1024 = hybrid_kem::encapsulation_key_1024(&self.mlkem_seed);
        crate::arsenic::HybridRecipient::new_with_1024(
            self.public_key, *self.mlkem_public_key, mlkem_1024,
        )
    }
}

/// A named hybrid (X25519 + ML-KEM-768) public key belonging to a contact.
#[derive(Clone)]
pub struct ContactEntry {
    pub name: String,
    /// X25519 public key.
    pub public_key: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub mlkem_public_key: Box<[u8; 1184]>,
    /// ML-DSA-65 verifying key (1952 bytes) — trusted signing key for this contact.
    /// `None` if the contact has not shared their signing public key yet.
    pub signing_verifying_key: Option<Box<[u8; 1952]>>,
}

impl ContactEntry {
    /// Build a `HybridRecipient` for encrypting to this contact.
    pub fn as_recipient(&self) -> crate::arsenic::HybridRecipient {
        crate::arsenic::HybridRecipient::new(self.public_key, *self.mlkem_public_key)
    }
}

/// Serialize a `SigningKeyEntry` as a shareable `.sigpub` file (verifying key only, no seed).
pub fn serialize_sign_pubkey(entry: &SigningKeyEntry) -> String {
    let vk_enc = encode_mldsa_vk(&entry.verifying_key);
    format!(
        "# Arsenic signing public key — share this file so correspondents can verify your signatures.\n\
         # name: {}\n\
         # sign-key: {}\n",
        entry.name, vk_enc,
    )
}

/// Parse a `.sigpub` file and return `(name, verifying_key)`.
pub fn parse_sign_pubkey_file(content: &str, path: std::path::PathBuf) -> Option<(String, [u8; 1952])> {
    let mut name = String::new();
    let mut vk: Option<[u8; 1952]> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# name:") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("# sign-key:") {
            vk = decode_mldsa_vk(rest.trim());
        }
    }

    if name.is_empty() {
        name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    }
    Some((name, vk?))
}

// ── Short display ─────────────────────────────────────────────────────────────

pub fn pubkey_short(bytes: &[u8; 32]) -> String {
    let full = encode_pubkey(bytes);
    format!("{}…{}", &full[..14], &full[full.len() - 4..])
}

// ── Platform paths ────────────────────────────────────────────────────────────

fn config_base() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    return std::env::var("APPDATA").ok().map(Into::into);

    #[cfg(target_os = "macos")]
    {
        let home: PathBuf = std::env::var("HOME").ok()?.into();
        return Some(home.join("Library/Application Support"));
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Some(
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home: PathBuf = std::env::var("HOME").unwrap_or_default().into();
                    home.join(".config")
                }),
        )
    }
}

/// `{config}/cryptyrust/keys/` — created on first access.
pub fn keys_dir() -> Option<PathBuf> {
    let dir = config_base()?.join("cryptyrust").join("keys");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// `{config}/cryptyrust/contacts`
pub fn contacts_path() -> Option<PathBuf> {
    let dir = config_base()?.join("cryptyrust");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("contacts"))
}

// ── Timestamp ─────────────────────────────────────────────────────────────────

pub fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = unix_to_datetime(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn unix_to_datetime(mut secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60; secs /= 60;
    let mi = secs % 60; secs /= 60;
    let h = secs % 24; secs /= 24;
    let mut y = 1970u64;
    let mut rem = secs;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if rem < dy { break; }
        rem -= dy; y += 1;
    }
    let months = [31u64, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u64;
    for &dm in &months {
        if rem < dm { break; }
        rem -= dm; mo += 1;
    }
    (y, mo, rem + 1, h, mi, s)
}

fn is_leap(y: u64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

// ── Identity file format ──────────────────────────────────────────────────────

/// Serialize the **public** parts of a keypair as a shareable `.pubkey` file.
///
/// If `signing_vk` is provided, the ML-DSA-65 verifying key is included so
/// the recipient can both encrypt for this identity **and** verify its signatures
/// from a single file exchange.
pub fn serialize_pubkey(entry: &KeyEntry) -> String {
    let pub_enc   = encode_pubkey(&entry.public_key);
    let mlkem_enc = encode_mlkem_pubkey(&entry.mlkem_public_key);
    let mut s = format!(
        "# Arsenic identity — share with correspondents (encryption key + signing key).\n\
         # name: {name}\n\
         # public key: {pub_enc}\n\
         # mlkem-public-key: {mlkem_enc}\n",
        name = entry.name,
    );
    if let Some(ref vk) = entry.signing_verifying_key {
        s.push_str(&format!("# sign-key: {}\n", encode_mldsa_vk(vk)));
    }
    s
}

/// Parse a `.pubkey` **or** `.key` file and return a `ContactEntry`.
///
/// Reads encryption keys and, if present, the `# sign-key:` ML-DSA-65 verifying
/// key. Private key / seed lines are silently ignored.
pub fn parse_pubkey_file(content: &str, path: std::path::PathBuf) -> Option<ContactEntry> {
    let mut name = String::new();
    let mut public_key: Option<[u8; 32]>    = None;
    let mut mlkem_key:  Option<[u8; 1184]>  = None;
    let mut sign_vk:    Option<[u8; 1952]>  = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# name:") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("# public key:") {
            public_key = decode_pubkey(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# mlkem-public-key:") {
            mlkem_key = decode_mlkem_pubkey(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# sign-key:") {
            sign_vk = decode_mldsa_vk(rest.trim());
        }
        // Private key / seed lines silently skipped.
    }

    if name.is_empty() {
        name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
    }

    Some(ContactEntry {
        name,
        public_key:            public_key?,
        mlkem_public_key:      Box::new(mlkem_key?),
        signing_verifying_key: sign_vk.map(Box::new),
    })
}

pub fn serialize_identity(entry: &KeyEntry) -> String {
    let ts = utc_timestamp();
    let pub_enc   = encode_pubkey(&entry.public_key);
    let mlkem_enc = encode_mlkem_pubkey(&entry.mlkem_public_key);
    let priv_enc  = encode_privkey(&entry.private_key);
    let seed_enc  = encode_mlkem_seed(&entry.mlkem_seed);
    let mut s = format!(
        "# created: {ts}\n# name: {name}\n# public key: {pub_enc}\n\
         # mlkem-public-key: {mlkem_enc}\n# mlkem-seed: {seed_enc}\n",
        name = entry.name,
    );
    if let (Some(ref sign_seed), Some(ref sign_vk)) = (&entry.signing_seed, &entry.signing_verifying_key) {
        let sign_seed_enc = format!("ARSENIC-SIGN-SEED-1{}", bech32_encode_upper(&**sign_seed));
        let sign_vk_enc   = encode_mldsa_vk(sign_vk);
        s.push_str(&format!("# sign-pub: {sign_vk_enc}\n# sign-seed: {sign_seed_enc}\n"));
    }
    s.push_str(&format!("{priv_enc}\n"));
    s
}

/// Parse one identity file. Returns `None` if no private key line is found.
///
/// If the file contains `# mlkem-seed:`, that independent seed is used.
/// Otherwise the seed is derived from the X25519 key via BLAKE3 (legacy compat).
pub fn parse_identity(content: &str, path: PathBuf) -> Option<KeyEntry> {
    let mut name = String::new();
    let mut public_key: Option<[u8; 32]> = None;
    let mut private_key: Option<[u8; 32]> = None;
    let mut mlkem_seed: Option<[u8; 64]> = None;
    let mut signing_seed: Option<Zeroizing<[u8; 32]>> = None;
    let mut signing_vk: Option<[u8; 1952]> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# name:") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("# public key:") {
            public_key = decode_pubkey(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# mlkem-seed:") {
            mlkem_seed = decode_mlkem_seed(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# sign-pub:") {
            signing_vk = decode_mldsa_vk(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# sign-seed:") {
            let upper = rest.trim().to_uppercase();
            if let Some(inner) = upper.strip_prefix("ARSENIC-SIGN-SEED-1") {
                signing_seed = bech32_decode_lower(&inner.to_lowercase())
                    .and_then(|v: Vec<u8>| v.try_into().ok())
                    .map(Zeroizing::new);
            }
        } else if !line.starts_with('#') && !line.is_empty() {
            private_key = decode_privkey(line);
        }
    }

    let private_key = private_key?;
    let public_key = public_key.unwrap_or_else(|| pubkey_from_privkey(&private_key));
    let mlkem_seed = mlkem_seed.unwrap_or_else(|| hybrid_kem::seed_from_x25519(&private_key));
    let mlkem_public_key = Box::new(hybrid_kem::encapsulation_key_768(&mlkem_seed));

    // Derive sign_vk from signing_seed if vk not stored (or verify consistency).
    let (signing_seed, signing_verifying_key) = match signing_seed {
        Some(seed) => {
            let vk = signing_vk.unwrap_or_else(|| {
                let arr: MlDsaSeed = (*seed).into();
                let sk = MlDsaSignKey::<MlDsa65>::from_seed(&arr);
                let vk_enc = KeyExport::to_bytes(&Keypair::verifying_key(&sk));
                let mut out = [0u8; 1952];
                out.copy_from_slice(vk_enc.as_slice());
                out
            });
            (Some(seed), Some(Box::new(vk)))
        }
        None => (None, None), // legacy key — no signing capability
    };

    if name.is_empty() {
        name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    }
    Some(KeyEntry {
        name, private_key, mlkem_seed, public_key, mlkem_public_key,
        signing_seed, signing_verifying_key, file_path: Some(path),
    })
}

/// Load an identity from a standalone file (not necessarily in the keystore).
pub fn load_identity_file(path: &Path) -> Option<KeyEntry> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_identity(&content, path.to_path_buf())
}

// ── Load / save keypairs ──────────────────────────────────────────────────────

pub fn load_keystore() -> Vec<KeyEntry> {
    let Some(dir) = keys_dir() else { return vec![] };
    let Ok(entries) = std::fs::read_dir(&dir) else { return vec![] };
    let mut keys: Vec<KeyEntry> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "key").unwrap_or(false))
        .filter_map(|e| {
            let path = e.path();
            let content = std::fs::read_to_string(&path).ok()?;
            parse_identity(&content, path)
        })
        .collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    keys
}

pub fn save_key(entry: &mut KeyEntry) -> Result<(), String> {
    let dir = keys_dir().ok_or("cannot determine config directory")?;
    let path = match &entry.file_path {
        Some(p) => p.clone(),
        None => unique_key_path(&dir, &entry.name),
    };
    let content = serialize_identity(entry);
    write_key_file(&path, &content).map_err(|e| e.to_string())?;
    entry.file_path = Some(path);
    Ok(())
}

pub fn delete_key(entry: &KeyEntry) {
    if let Some(ref path) = entry.file_path {
        let _ = std::fs::remove_file(path);
    }
}

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect();
    let s = s.trim_matches('_').to_lowercase();
    let s = if s.is_empty() { "key".to_string() } else { s };
    s.chars().take(64).collect()
}

fn unique_key_path(dir: &Path, name: &str) -> PathBuf {
    let base = sanitize_filename(name);
    let candidate = dir.join(format!("{base}.key"));
    if !candidate.exists() { return candidate; }
    for n in 2u32.. {
        let c = dir.join(format!("{base}_{n}.key"));
        if !c.exists() { return c; }
    }
    unreachable!()
}

#[cfg(unix)]
fn write_key_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(content.as_bytes())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}

// ── Load / save contacts ──────────────────────────────────────────────────────

pub fn load_contacts() -> Vec<ContactEntry> {
    let Some(path) = contacts_path() else { return vec![] };
    let Ok(data) = std::fs::read_to_string(&path) else { return vec![] };
    parse_contacts(&data)
}

pub fn save_contacts(contacts: &[ContactEntry]) {
    let Some(path) = contacts_path() else { return };
    let _ = std::fs::write(path, serialize_contacts(contacts));
}

fn parse_contacts(data: &str) -> Vec<ContactEntry> {
    let mut result = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut pending_x25519: Option<[u8; 32]> = None;
    let mut pending_mlkem: Option<[u8; 1184]> = None;
    let mut pending_sign_vk: Option<[u8; 1952]> = None;

    let flush = |name: Option<String>,
                 x25519: Option<[u8; 32]>,
                 mlkem: Option<[u8; 1184]>,
                 sign_vk: Option<[u8; 1952]>,
                 result: &mut Vec<ContactEntry>| {
        if let (Some(n), Some(k), Some(m)) = (name, x25519, mlkem) {
            result.push(ContactEntry {
                name: n,
                public_key: k,
                mlkem_public_key: Box::new(m),
                signing_verifying_key: sign_vk.map(|v| Box::new(v)),
            });
        }
    };

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Some(rest) = line.strip_prefix("# mlkem:") {
            pending_mlkem = decode_mlkem_pubkey(rest.trim());
        } else if let Some(rest) = line.strip_prefix("# sign-key:") {
            pending_sign_vk = decode_mldsa_vk(rest.trim());
            // flush once we have mlkem (sign-key comes after mlkem in the file)
            if pending_mlkem.is_some() {
                flush(
                    pending_name.take(), pending_x25519.take(),
                    pending_mlkem.take(), pending_sign_vk.take(), &mut result,
                );
            }
        } else if let Some(rest) = line.strip_prefix('#') {
            // flush previous entry if any (no sign-key line → flush on new name)
            if pending_mlkem.is_some() {
                flush(
                    pending_name.take(), pending_x25519.take(),
                    pending_mlkem.take(), pending_sign_vk.take(), &mut result,
                );
            }
            pending_name = Some(rest.trim().to_string());
            pending_x25519 = None;
            pending_sign_vk = None;
        } else if let Some(key) = decode_pubkey(line) {
            pending_x25519 = Some(key);
        }
    }
    // flush last pending entry
    if pending_mlkem.is_some() {
        flush(pending_name, pending_x25519, pending_mlkem, pending_sign_vk, &mut result);
    }
    result
}

fn serialize_contacts(contacts: &[ContactEntry]) -> String {
    contacts
        .iter()
        .map(|c| {
            let mut s = format!(
                "# {}\n{}\n# mlkem:{}\n",
                c.name,
                encode_pubkey(&c.public_key),
                encode_mlkem_pubkey(&c.mlkem_public_key),
            );
            if let Some(ref vk) = c.signing_verifying_key {
                s.push_str(&format!("# sign-key:{}\n", encode_mldsa_vk(vk)));
            }
            s
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── ML-DSA-65 signing key store ───────────────────────────────────────────────

/// A named ML-DSA-65 signing keypair stored as a `.sigkey` file.
///
/// Only the 32-byte seed is stored. The signing key and verifying key are
/// reconstructed from the seed via `SigningKey::from_seed`.
#[derive(Clone)]
pub struct SigningKeyEntry {
    pub name: String,
    /// ML-DSA-65 seed (32 bytes), zeroized on drop.
    pub seed: Zeroizing<[u8; 32]>,
    /// ML-DSA-65 verifying key (1952 bytes), derived from `seed`.
    pub verifying_key: Box<[u8; 1952]>,
    pub file_path: Option<PathBuf>,
}

impl SigningKeyEntry {
    pub fn generate(name: String) -> Self {
        use crate::random_bytes_32;
        let seed = random_bytes_32();
        let seed_common: ml_dsa::Seed = seed.into();
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_common);
        let vk = <ml_dsa::SigningKey<ml_dsa::MlDsa65> as ml_dsa::Keypair>::verifying_key(&sk);
        let vk_enc = vk.encode();
        let mut vk_arr = [0u8; 1952];
        vk_arr.copy_from_slice(vk_enc.as_slice());
        Self { name, seed: Zeroizing::new(seed), verifying_key: Box::new(vk_arr), file_path: None }
    }
}

/// `{config}/cryptyrust/signing-keys/` — created on first access.
pub fn signing_keys_dir() -> Option<PathBuf> {
    let dir = config_base()?.join("cryptyrust").join("signing-keys");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

pub fn serialize_signing_identity(entry: &SigningKeyEntry) -> String {
    
    let ts = utc_timestamp();
    // Encode seed as ARSENIC-SIGN-SEED-1{BECH32}
    let seed_enc = format!("ARSENIC-SIGN-SEED-1{}", crate::keyfmt::bech32_encode_upper(&*entry.seed));
    // Encode verifying key as ARSENIC-SIGN-PUB-1{BECH32}
    let vk_enc = format!("ARSENIC-SIGN-PUB-1{}", crate::keyfmt::bech32_encode_upper(entry.verifying_key.as_slice()));
    format!(
        "# created: {ts}\n# name: {}\n# verifying-key: {}\n{}\n",
        entry.name, vk_enc, seed_enc,
    )
}

pub fn parse_signing_identity(content: &str, path: PathBuf) -> Option<SigningKeyEntry> {
    let mut name = String::new();
    let mut seed: Option<Zeroizing<[u8; 32]>> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# name:") {
            name = rest.trim().to_string();
        } else if !line.starts_with('#') && !line.is_empty() {
            let upper = line.to_uppercase();
            if let Some(inner) = upper.strip_prefix("ARSENIC-SIGN-SEED-1") {
                if let Some(bytes) = crate::keyfmt::bech32_decode_lower(&inner.to_lowercase()) {
                    seed = bytes.try_into().ok().map(Zeroizing::new);
                }
            }
        }
    }

    let seed = seed?;
    let seed_common: ml_dsa::Seed = (*seed).into();
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_common);
    let vk = <ml_dsa::SigningKey<ml_dsa::MlDsa65> as ml_dsa::Keypair>::verifying_key(&sk);
    let vk_enc = vk.encode();
    let mut vk_arr = [0u8; 1952];
    vk_arr.copy_from_slice(vk_enc.as_slice());
    if name.is_empty() {
        name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    }
    Some(SigningKeyEntry { name, seed, verifying_key: Box::new(vk_arr), file_path: Some(path) })
}

pub fn load_signing_identity_file(path: &Path) -> Option<SigningKeyEntry> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_signing_identity(&content, path.to_path_buf())
}

pub fn save_signing_key(entry: &mut SigningKeyEntry) -> Result<(), String> {
    let dir = signing_keys_dir().ok_or("cannot determine signing-keys directory")?;
    let path = match &entry.file_path {
        Some(p) => p.clone(),
        None => {
            let base = sanitize_filename(&entry.name);
            dir.join(format!("{base}.sigkey"))
        }
    };
    let content = serialize_signing_identity(entry);
    write_key_file(&path, &content).map_err(|e| e.to_string())?;
    entry.file_path = Some(path);
    Ok(())
}

pub fn load_signing_keystore() -> Vec<SigningKeyEntry> {
    let Some(dir) = signing_keys_dir() else { return vec![] };
    let Ok(entries) = std::fs::read_dir(&dir) else { return vec![] };
    let mut keys: Vec<SigningKeyEntry> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "sigkey").unwrap_or(false))
        .filter_map(|e| {
            let path = e.path();
            let content = std::fs::read_to_string(&path).ok()?;
            parse_signing_identity(&content, path)
        })
        .collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    keys
}

/// Resolve a signing key by name or file path.
pub fn resolve_signing_key(spec: &str) -> Option<SigningKeyEntry> {
    let path = Path::new(spec);
    if path.exists() {
        return load_signing_identity_file(path);
    }
    load_signing_keystore()
        .into_iter()
        .find(|k| k.name.eq_ignore_ascii_case(spec))
}

/// Resolve a recipient string to a `HybridRecipient`:
/// - `arsenic1...`   → X25519-only key (cannot build hybrid — returns None; use full hybrid key)
/// - `arsenic1m...`  → ML-KEM key alone (incomplete — returns None)
/// - contact name    → lookup in contacts keystore (needs both keys stored)
/// - file path       → read identity file and return its hybrid public keys
///
/// For contacts, both X25519 and ML-KEM keys must be present (hybrid contacts).
pub fn resolve_recipient(spec: &str) -> Option<crate::arsenic::HybridRecipient> {
    // Identity file path
    let path = Path::new(spec);
    if path.exists() {
        return load_identity_file(path).map(|k| k.as_recipient());
    }
    // Contact by name
    load_contacts()
        .into_iter()
        .find(|c| c.name.eq_ignore_ascii_case(spec))
        .map(|c| c.as_recipient())
}
