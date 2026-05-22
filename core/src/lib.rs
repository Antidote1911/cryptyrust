mod config;
mod constants;
mod crypto;
mod errors;
mod header;
mod keygen;
mod secret;

pub use crate::config::*;
pub use crate::constants::*;
pub use crate::crypto::*;
pub use crate::errors::CoreErr;
pub use crate::secret::*;

use std::fs::{remove_file, File};
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
