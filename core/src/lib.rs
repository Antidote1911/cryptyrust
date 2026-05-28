pub mod arsenic;
mod config;
mod constants;
mod errors;
mod secret;

pub use crate::arsenic::{ArsenicParams, ArsenicStrength, CipherId};
pub use crate::config::{Direction, Ui};
pub use crate::constants::*;
pub use crate::errors::CoreErr;
pub use crate::secret::*;

use std::fs::{remove_file, File, OpenOptions};
use std::time::Instant;

pub const fn get_version() -> &'static str {
    APP_VERSION
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
        hdr_cipher: arsenic::CipherId::from_byte(pub_hdr.hdr_cipher_id).ok()?,
        pld_cipher: arsenic::CipherId::from_byte(pub_hdr.pld_cipher_id).ok()?,
    })
}

/// Change the password of an Arsenic V2 file without decrypting the payload.
///
/// A 256-byte backup of the current header is written to `<path>.bak` and
/// flushed to disk before the in-place write begins.  On success the backup
/// is removed.  If the process is interrupted (power cut, crash) the backup
/// remains and is automatically used to restore the header on the next call.
pub fn arsenic_rekey(
    path: &std::path::Path,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    use std::io::{Read, Write};

    let bak_path = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".bak");
        path.with_file_name(name)
    };

    // ── Detect and handle an interrupted previous rekey ───────────────────
    if bak_path.exists() {
        // Check whether the main file still starts with the "ARSN" magic.
        let magic_intact = {
            let mut magic = [0u8; 4];
            File::open(path)
                .and_then(|mut f| f.read_exact(&mut magic))
                .is_ok_and(|_| magic == arsenic::header::MAGIC)
        };

        if !magic_intact {
            // The in-place write was interrupted mid-header.  Restore from backup.
            let backup = std::fs::read(&bak_path)?;
            if backup.len() == arsenic::header::TOTAL_HEADER_LEN {
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
        // Magic intact → the previous rekey succeeded but cleanup was skipped.
        // The stale backup will be overwritten in the next step.
    }

    // ── Save current 256-byte header to backup, flush to disk ────────────
    {
        let mut current_hdr = [0u8; arsenic::header::TOTAL_HEADER_LEN];
        File::open(path)?.read_exact(&mut current_hdr)?;
        let mut bak = File::create(&bak_path)?;
        bak.write_all(&current_hdr)?;
        // sync_all() ensures the backup is on physical storage before we
        // modify the source file.
        bak.sync_all()?;
    }

    // ── Perform the in-place rekey ────────────────────────────────────────
    let result = {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        arsenic::rekey_arsenic(&mut f, old_password, new_password, ui)
    };

    // ── Remove backup only after a confirmed success ──────────────────────
    if result.is_ok() {
        let _ = remove_file(&bak_path);
    }

    result
}

/// Detect whether a file starts with the Arsenic V2 magic ("ARSN").
pub fn is_arsenic_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .is_ok_and(|_| magic == arsenic::header::MAGIC)
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
