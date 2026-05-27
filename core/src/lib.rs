mod config;
mod constants;
mod crypto;
mod errors;
mod header;
mod keygen;
pub mod pem;
mod secret;
pub mod arsenic;

pub use crate::config::*;
pub use crate::constants::*;
pub use crate::crypto::*;
pub use crate::errors::CoreErr;
pub use crate::secret::*;
pub use crate::arsenic::{ArsenicParams, ArsenicStrength};

use std::fs::{remove_file, File, OpenOptions};
use std::time::Instant;

pub const fn get_version() -> &'static str {
    APP_VERSION
}

pub fn main_routine(c: &Config) -> Result<f64, CoreErr> {
    let mut in_file = File::open(c.filename.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no input filename provided",
        )
    })?)?;
    let mut out_file = File::create(c.out_file.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no output filename provided",
        )
    })?)?;
    let filesize = in_file.metadata()?.len();

    let start = Instant::now();
    match c.direction {
        Direction::Encrypt => {
            if let Err(e) = encrypt(
                &mut in_file,
                &mut out_file,
                &c.password,
                &*c.ui,
                filesize,
                c.algorithm,
                c.derivestrength,
                c.hashmode,
                c.benchmode,
            ) {
                if let Some(out_file) = &c.out_file {
                    let _ = remove_file(out_file);
                }
                return Err(e);
            }
        }
        Direction::Decrypt => {
            if let Err(e) = decrypt(
                &mut in_file,
                &mut out_file,
                &c.password,
                &*c.ui,
                filesize,
                c.hashmode,
                c.benchmode,
            ) {
                if let Some(out_file) = &c.out_file {
                    let _ = remove_file(out_file);
                }
                return Err(e);
            }
        }
    }
    let duration = start.elapsed().as_secs_f64();
    Ok(duration)
}

/// Read the Argon2id parameters stored in an Arsenic V2 file header.
/// Returns `None` if the file cannot be read or is not a valid Arsenic V2 file.
pub fn arsenic_read_params(path: &std::path::Path) -> Option<ArsenicParams> {
    use std::io::Read;
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; arsenic::header::TOTAL_HEADER_LEN];
    f.read_exact(&mut buf).ok()?;
    let (pub_hdr, _, _, _) = arsenic::header::parse_header_bytes(&buf).ok()?;
    Some(ArsenicParams {
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
    })
}

/// Change the password of an Arsenic V2 file without decrypting the payload.
///
/// Only the 256-byte header is rewritten: a fresh Argon2id salt is generated,
/// the DEK envelope is re-encrypted under the new KEK, and the header MAC is
/// recomputed. The payload blocks are not touched.
pub fn arsenic_rekey(
    path: &std::path::Path,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    arsenic::rekey_arsenic(&mut f, old_password, new_password, ui)
}

/// Detect whether a file starts with the Arsenic V2 magic ("ARSN").
pub fn is_arsenic_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).map_or(false, |_| magic == arsenic::header::MAGIC)
}

/// Encrypt or decrypt a file in Arsenic V2 format.
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
