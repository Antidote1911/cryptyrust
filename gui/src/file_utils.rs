use cryptyrust_core::ArsenicStrength;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const ARSENIC_MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"

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
    f.read_exact(&mut magic).is_ok() && magic == ARSENIC_MAGIC
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

/// Atomically claims a unique output path using `create_new` (O_CREAT|O_EXCL).
/// Returns the path string and the open empty File handle.
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
