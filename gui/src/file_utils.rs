use cryptyrust_core::{Algorithm, DeriveStrength};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const CRYPTYRUST_MAGIC: [u8; 4] = [0x43, 0x52, 0x59, 0x50];

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub fn is_cryptyrust_file(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_ok() && magic == CRYPTYRUST_MAGIC {
        return true;
    }
    crate::pem::is_pem_cryptyrust_file(path)
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

pub fn algo_label(a: Algorithm) -> &'static str {
    match a {
        Algorithm::XChaCha20Poly1305 => "XChaCha20Poly1305",
        Algorithm::Aes256Gcm => "AES-256-GCM",
        Algorithm::Aes256GcmSiv => "AES-256-GCM-SIV",
    }
}

pub fn derive_label(d: DeriveStrength) -> &'static str {
    match d {
        DeriveStrength::Interactive => "Interactive",
        DeriveStrength::Moderate => "Moderate",
        DeriveStrength::Sensitive => "Sensitive",
    }
}

/// Atomically claims a unique output path using `create_new` (O_CREAT|O_EXCL).
/// Returns the path string and the open empty File handle.
/// Keep the handle alive until the actual write completes to prevent another
/// concurrent thread from claiming the same filename.
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

/// Reads the first 10 bytes of a cryptyrust file to extract algorithm and derive strength.
/// Returns None if the file is not a valid cryptyrust file or cannot be read.
pub fn read_encryption_info(path: &Path) -> Option<(Algorithm, DeriveStrength)> {
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; 10];
    f.read_exact(&mut buf).ok()?;

    // Magic: [0x43, 0x52, 0x59, 0x50]
    if buf[0..4] != [0x43, 0x52, 0x59, 0x50] {
        return None;
    }

    // bytes 6-7: algorithm
    let algo = match [buf[6], buf[7]] {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::Aes256Gcm,
        [0x0E, 0x03] => Algorithm::Aes256GcmSiv,
        _ => return None,
    };

    // bytes 8-9: derive strength
    let derive = match [buf[8], buf[9]] {
        [0xBE, 0x01] => DeriveStrength::Interactive,
        [0xBE, 0x02] => DeriveStrength::Moderate,
        [0xBE, 0x03] => DeriveStrength::Sensitive,
        _ => return None,
    };

    Some((algo, derive))
}
