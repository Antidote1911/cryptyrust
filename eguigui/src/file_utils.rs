use std::fs::File;
use std::io::Read;
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
    matches!(f.read_exact(&mut magic), Ok(_) if magic == CRYPTYRUST_MAGIC)
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

pub fn algo_label(a: cryptyrust_core::Algorithm) -> &'static str {
    match a {
        cryptyrust_core::Algorithm::XChaCha20Poly1305 => "XChaCha20Poly1305",
        cryptyrust_core::Algorithm::Aes256Gcm => "AES-256-GCM",
        cryptyrust_core::Algorithm::Aes256GcmSiv => "AES-256-GCM-SIV",
    }
}