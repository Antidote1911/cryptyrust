use arsenic::{ArsenicStrength, CipherId};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const ARSENIC_MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"
const ARMOR_HEADER: &[u8] = b"-----BEGIN ARSENIC";

#[derive(PartialEq, Clone, Copy, Debug)]
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


pub fn detect_mode(files: &[PathBuf]) -> Option<Mode> {
    if files.is_empty() {
        return Some(Mode::Encrypt);
    }
    let enc = files.iter().filter(|p| is_cryptyrust_file(p)).count();
    if enc == files.len() {
        Some(Mode::Decrypt)
    } else if enc == 0 {
        Some(Mode::Encrypt)
    } else {
        None
    }
}

pub fn get_file_size(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            let size = metadata.len();
            if size < 1024 {
                format!("{} B", size)
            } else if size < 1024 * 1024 {
                format!("{} KB", size / 1024)
            } else if size < 1024 * 1024 * 1024 {
                format!("{} MB", size / (1024 * 1024))
            } else {
                format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}

pub fn arsenic_strength_label(s: ArsenicStrength) -> &'static str {
    match s {
        ArsenicStrength::Interactive => "Interactive  (256 MB)",
        ArsenicStrength::Sensitive => "Sensitive  (1 GB)",
    }
}

pub fn cipher_label(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "Deoxys-II-256",
        CipherId::Aes256GcmSiv => "AES-256-GCM-SIV",
        CipherId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
    }
}

pub fn cipher_short_label(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "Deoxys-II",
        CipherId::Aes256GcmSiv => "AES-GCM-SIV",
        CipherId::XChaCha20Poly1305 => "XChaCha20",
    }
}

pub fn cipher_to_key(c: CipherId) -> &'static str {
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

/// Atomically claims a unique output path using `create_new` (O_CREAT|O_EXCL).
/// Returns the path string and the open empty File handle (keeps the slot claimed).
pub fn create_unique_output_file(base: &str, ext: &str) -> io::Result<(String, File)> {
    let candidate = format!("{}{}", base, ext);
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
        let candidate = format!("{} ({}){}", base, n, ext);
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
