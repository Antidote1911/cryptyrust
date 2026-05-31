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
use std::path::{Path, PathBuf};

// ── Types ─────────────────────────────────────────────────────────────────────

/// A named hybrid (X25519 + ML-KEM-768) keypair stored as an individual `.key` file.
///
/// Both keys are derived from the single 32-byte `private_key` stored on disk.
/// The ML-KEM encapsulation key is recomputed at load time and cached here.
#[derive(Clone)]
pub struct KeyEntry {
    pub name: String,
    /// X25519 private key — also the root seed for ML-KEM derivation.
    pub private_key: [u8; 32],
    /// X25519 public key (derived from private_key).
    pub public_key: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes, derived from private_key).
    pub mlkem_public_key: Box<[u8; 1184]>,
    /// Path of the `.key` file on disk (`None` before first save).
    pub file_path: Option<PathBuf>,
}

impl KeyEntry {
    pub fn generate(name: String) -> Self {
        let (private_key, public_key) = generate_x25519_keypair();
        let mlkem_public_key = Box::new(hybrid_kem::encapsulation_key(&private_key));
        Self { name, private_key, public_key, mlkem_public_key, file_path: None }
    }

    /// Build a `HybridRecipient` for encrypting to this key.
    pub fn as_recipient(&self) -> crate::arsenic::HybridRecipient {
        crate::arsenic::HybridRecipient::new(self.public_key, *self.mlkem_public_key)
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
}

impl ContactEntry {
    /// Build a `HybridRecipient` for encrypting to this contact.
    pub fn as_recipient(&self) -> crate::arsenic::HybridRecipient {
        crate::arsenic::HybridRecipient::new(self.public_key, *self.mlkem_public_key)
    }
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

pub fn serialize_identity(entry: &KeyEntry) -> String {
    let ts = utc_timestamp();
    let pub_enc = encode_pubkey(&entry.public_key);
    let mlkem_enc = encode_mlkem_pubkey(&entry.mlkem_public_key);
    let priv_enc = encode_privkey(&entry.private_key);
    format!(
        "# created: {ts}\n# name: {name}\n# public key: {pub_enc}\n# mlkem-public-key: {mlkem_enc}\n{priv_enc}\n",
        name = entry.name,
    )
}

/// Parse one identity file. Returns `None` if no private key line is found.
/// The ML-KEM encapsulation key is always re-derived from the private key.
pub fn parse_identity(content: &str, path: PathBuf) -> Option<KeyEntry> {
    let mut name = String::new();
    let mut public_key: Option<[u8; 32]> = None;
    let mut private_key: Option<[u8; 32]> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# name:") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("# public key:") {
            public_key = decode_pubkey(rest.trim());
        } else if !line.starts_with('#') && !line.is_empty() {
            private_key = decode_privkey(line);
        }
        // "# mlkem-public-key:" is written for human inspection but we always re-derive.
    }

    let private_key = private_key?;
    let public_key = public_key.unwrap_or_else(|| pubkey_from_privkey(&private_key));
    let mlkem_public_key = Box::new(hybrid_kem::encapsulation_key(&private_key));
    if name.is_empty() {
        name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    Some(KeyEntry { name, private_key, public_key, mlkem_public_key, file_path: Some(path) })
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

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Some(rest) = line.strip_prefix("# mlkem:") {
            // ML-KEM line follows a # name: line and an arsenic1 line
            if let (Some(name), Some(x25519)) = (pending_name.take(), pending_x25519.take()) {
                if let Some(mlkem) = decode_mlkem_pubkey(rest.trim()) {
                    result.push(ContactEntry {
                        name,
                        public_key: x25519,
                        mlkem_public_key: Box::new(mlkem),
                    });
                }
            }
        } else if let Some(rest) = line.strip_prefix('#') {
            pending_name = Some(rest.trim().to_string());
            pending_x25519 = None;
        } else if let Some(key) = decode_pubkey(line) {
            pending_x25519 = Some(key);
        }
    }
    result
}

fn serialize_contacts(contacts: &[ContactEntry]) -> String {
    contacts
        .iter()
        .map(|c| format!(
            "# {}\n{}\n# mlkem:{}\n",
            c.name,
            encode_pubkey(&c.public_key),
            encode_mlkem_pubkey(&c.mlkem_public_key),
        ))
        .collect::<Vec<_>>()
        .join("\n")
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
