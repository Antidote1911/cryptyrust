use arsenic::{ArsenicStrength, CipherId};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

const ARSENIC_MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"
const ARMOR_HEADER: &[u8] = b"-----BEGIN ARSENIC";

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Returns true if the file is an Arsenic encrypted file — either binary (.arsn)
/// or ASCII-armored (.arsn.armor).
pub fn is_cryptyrust_file(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut buf = [0u8; 18]; // enough to match both magic and armor header
    let n = f.read(&mut buf).unwrap_or(0);
    let bytes = &buf[..n];
    bytes.starts_with(&ARSENIC_MAGIC) || bytes.starts_with(ARMOR_HEADER)
}


/// Returns true if the file starts with the ASCII-armor header. Reads only the
/// first bytes, so it is safe to call on very large files.
pub fn is_armored_file(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut buf = [0u8; 18];
    let n = f.read(&mut buf).unwrap_or(0);
    buf[..n].starts_with(ARMOR_HEADER)
}

/// What the file list shows for one file. Computed once when the file is added
/// instead of on every frame.
#[derive(Clone, Debug)]
pub struct FileMeta {
    /// Arsenic file, binary or armored.
    pub encrypted: bool,
    /// ASCII-armored Arsenic file.
    pub armored: bool,
    pub size: String,
}

impl FileMeta {
    pub fn read(path: &Path) -> Self {
        let armored = is_armored_file(path);
        Self {
            encrypted: armored || is_cryptyrust_file(path),
            armored,
            size: get_file_size(path),
        }
    }
}

#[cfg(test)]
pub fn detect_mode(files: &[PathBuf]) -> Option<Mode> {
    mode_from_flags(files.iter().map(|p| is_cryptyrust_file(p)))
}

/// `Decrypt` if every file is encrypted, `Encrypt` if none is (or the list is
/// empty), `None` for a mix.
pub fn mode_from_flags(encrypted: impl IntoIterator<Item = bool>) -> Option<Mode> {
    let (mut total, mut enc) = (0usize, 0usize);
    for e in encrypted {
        total += 1;
        enc += usize::from(e);
    }
    if enc == 0 {
        Some(Mode::Encrypt)
    } else if enc == total {
        Some(Mode::Decrypt)
    } else {
        None
    }
}

/// Shortest password accepted when a password is being *set* (encryption,
/// password change, additional password). Never applied to decryption.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Check a password that is about to protect a file.
pub fn check_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("Password must be at least {MIN_PASSWORD_CHARS} characters."));
    }
    Ok(())
}

pub fn get_file_size(path: &Path) -> String {
    // Display only: the rounding of a u64 → f64 conversion is irrelevant here.
    #[allow(clippy::cast_precision_loss)]
    std::fs::metadata(path).map_or_else(
        |_| "Unknown".to_string(),
        |metadata| {
            let size = metadata.len();
            if size < 1024 {
                format!("{size} B")
            } else if size < 1024 * 1024 {
                format!("{} KB", size / 1024)
            } else if size < 1024 * 1024 * 1024 {
                format!("{} MB", size / (1024 * 1024))
            } else {
                format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
            }
        },
    )
}

pub const fn arsenic_strength_label(s: ArsenicStrength) -> &'static str {
    match s {
        ArsenicStrength::Interactive => "Interactive  (256 MB)",
        ArsenicStrength::Sensitive => "Sensitive  (1 GB)",
    }
}

pub const fn cipher_label(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "Deoxys-II-256",
        CipherId::Aes256GcmSiv => "AES-256-GCM-SIV",
        CipherId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
    }
}

pub const fn cipher_short_label(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "Deoxys-II",
        CipherId::Aes256GcmSiv => "AES-GCM-SIV",
        CipherId::XChaCha20Poly1305 => "XChaCha20",
    }
}

pub const fn cipher_to_key(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "deoxys_ii",
        CipherId::Aes256GcmSiv => "aes_gcm_siv",
        CipherId::XChaCha20Poly1305 => "xchacha20",
    }
}

pub fn cipher_from_key(s: &str) -> Option<CipherId> {
    match s {
        "deoxys_ii" => Some(CipherId::DeoxysII256),
        "aes_gcm_siv" => Some(CipherId::Aes256GcmSiv),
        "xchacha20" => Some(CipherId::XChaCha20Poly1305),
        _ => None,
    }
}

/// Atomically claims a unique output path using `create_new` (`O_CREAT|O_EXCL`).
/// Returns the path string and the open empty File handle (keeps the slot claimed).
pub fn create_unique_output_file(base: &str, ext: &str) -> io::Result<(String, File)> {
    let candidate = format!("{base}{ext}");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&candidate)
    {
        Ok(f) => return Ok((candidate, f)),
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let mut n = 1u32;
    loop {
        let candidate = format!("{base} ({n}){ext}");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
        n += 1;
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::{NamedTempFile, TempDir};

    // ── detect_mode ──────────────────────────────────────────────────────────

    #[test]
    fn detect_mode_empty_is_encrypt() {
        assert_eq!(detect_mode(&[]), Some(Mode::Encrypt));
    }

    #[test]
    fn detect_mode_all_plain_is_encrypt() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        assert_eq!(detect_mode(&[f.path().to_path_buf()]), Some(Mode::Encrypt));
    }

    #[test]
    fn detect_mode_all_arsenic_is_decrypt() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0x41, 0x52, 0x53, 0x4E, 0, 0, 0, 0]).unwrap();
        assert_eq!(detect_mode(&[f.path().to_path_buf()]), Some(Mode::Decrypt));
    }

    #[test]
    fn detect_mode_mixed_is_none() {
        let mut plain = NamedTempFile::new().unwrap();
        plain.write_all(b"plaintext").unwrap();
        let mut enc = NamedTempFile::new().unwrap();
        enc.write_all(&[0x41, 0x52, 0x53, 0x4E, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            detect_mode(&[plain.path().to_path_buf(), enc.path().to_path_buf()]),
            None,
        );
    }

    #[test]
    fn detect_mode_multiple_arsenic_is_decrypt() {
        let files: Vec<PathBuf> = (0..3)
            .map(|_| {
                let mut f = NamedTempFile::new().unwrap();
                f.write_all(&[0x41, 0x52, 0x53, 0x4E, 0, 0, 0, 0]).unwrap();
                f.into_temp_path().keep().unwrap()
            })
            .collect();
        assert_eq!(detect_mode(&files), Some(Mode::Decrypt));
        for p in files { let _ = std::fs::remove_file(p); }
    }

    #[test]
    fn file_meta_distinguishes_binary_and_armored() {
        let mut bin = NamedTempFile::new().unwrap();
        bin.write_all(&[0x41, 0x52, 0x53, 0x4E, 0, 0]).unwrap();
        let mut arm = NamedTempFile::new().unwrap();
        arm.write_all(b"-----BEGIN ARSENIC ENCRYPTED FILE-----\nAAAA\n").unwrap();
        let mut plain = NamedTempFile::new().unwrap();
        plain.write_all(b"hello").unwrap();

        let m = FileMeta::read(bin.path());
        assert!(m.encrypted && !m.armored);
        let m = FileMeta::read(arm.path());
        assert!(m.encrypted && m.armored);
        assert!(is_armored_file(arm.path()) && !is_armored_file(bin.path()));
        let m = FileMeta::read(plain.path());
        assert!(!m.encrypted && !m.armored);
        assert_eq!(m.size, "5 B");
    }

    #[test]
    fn new_password_needs_eight_characters() {
        assert!(check_new_password("1234567").is_err());
        assert!(check_new_password("12345678").is_ok());
        // Characters, not bytes: 7 accented letters are 14 bytes but too short.
        assert!(check_new_password("ééééééé").is_err());
        assert!(check_new_password("éééééééé").is_ok());
        assert!(check_new_password("").is_err());
    }

    // ── is_cryptyrust_file ───────────────────────────────────────────────────

    #[test]
    fn is_cryptyrust_file_with_arsenic_magic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0x41, 0x52, 0x53, 0x4E]).unwrap();
        assert!(is_cryptyrust_file(f.path()));
    }

    #[test]
    fn is_cryptyrust_file_wrong_magic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"PNG\x89").unwrap();
        assert!(!is_cryptyrust_file(f.path()));
    }

    #[test]
    fn is_cryptyrust_file_too_short() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"AR").unwrap();
        assert!(!is_cryptyrust_file(f.path()));
    }

    #[test]
    fn is_cryptyrust_file_nonexistent() {
        assert!(!is_cryptyrust_file(Path::new("/nonexistent/path/ghost.bin")));
    }

    // ── cipher_to_key / cipher_from_key ──────────────────────────────────────

    #[test]
    fn cipher_key_roundtrip_all_variants() {
        for c in [
            CipherId::DeoxysII256,
            CipherId::XChaCha20Poly1305,
            CipherId::Aes256GcmSiv,
        ] {
            let key = cipher_to_key(c);
            assert_eq!(cipher_from_key(key), Some(c), "roundtrip failed for {key}");
        }
    }

    #[test]
    fn cipher_from_key_unknown_is_none() {
        assert_eq!(cipher_from_key("unknown"), None);
        assert_eq!(cipher_from_key(""), None);
        assert_eq!(cipher_from_key("DeoxysII256"), None); // wrong case
    }

    // ── get_file_size ─────────────────────────────────────────────────────────

    #[test]
    fn get_file_size_bytes_range() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 512]).unwrap();
        let s = get_file_size(f.path());
        assert!(s.ends_with(" B"), "expected B suffix, got: {s}");
    }

    #[test]
    fn get_file_size_kilobytes_range() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 2048]).unwrap();
        let s = get_file_size(f.path());
        assert!(s.ends_with(" KB"), "expected KB suffix, got: {s}");
    }

    #[test]
    fn get_file_size_megabytes_range() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; 2 * 1024 * 1024]).unwrap();
        let s = get_file_size(f.path());
        assert!(s.ends_with(" MB"), "expected MB suffix, got: {s}");
    }

    #[test]
    fn get_file_size_nonexistent_is_unknown() {
        assert_eq!(get_file_size(Path::new("/no/such/file")), "Unknown");
    }

    // ── create_unique_output_file ─────────────────────────────────────────────

    #[test]
    fn create_unique_first_slot() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("out").to_string_lossy().to_string();
        let (path, _fh) = create_unique_output_file(&base, ".arsn").unwrap();
        assert_eq!(path, format!("{base}.arsn"));
        assert!(Path::new(&path).exists());
    }

    #[test]
    fn create_unique_skips_existing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("file").to_string_lossy().to_string();
        std::fs::write(format!("{base}.arsn"), b"taken").unwrap();
        let (path, _fh) = create_unique_output_file(&base, ".arsn").unwrap();
        assert_eq!(path, format!("{base} (1).arsn"));
    }

    #[test]
    fn create_unique_skips_multiple_existing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("f").to_string_lossy().to_string();
        std::fs::write(format!("{base}.arsn"), b"").unwrap();
        std::fs::write(format!("{base} (1).arsn"), b"").unwrap();
        let (path, _fh) = create_unique_output_file(&base, ".arsn").unwrap();
        assert_eq!(path, format!("{base} (2).arsn"));
    }

    #[test]
    fn create_unique_no_ext() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("plain").to_string_lossy().to_string();
        std::fs::write(&base, b"").unwrap();
        let (path, _fh) = create_unique_output_file(&base, "").unwrap();
        assert_eq!(path, format!("{base} (1)"));
    }
}
