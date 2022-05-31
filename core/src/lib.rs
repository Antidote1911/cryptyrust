mod crypto;
mod constants;
mod keygen;
mod config;
mod header;
mod errors;
mod secret;

pub use crate::errors::CoreErr;
pub use crate::constants::*;
pub use crate::config::*;
pub use crate::crypto::*;
pub use crate::secret::*;

use std::fs::{remove_file, File};
use std::time::Instant;

pub const fn get_version() -> &'static str {
    APP_VERSION
}

pub fn main_routine(c: &Config) -> Result<f64, CoreErr> {
    let in_file = match &c.filename {
        Some(s) => Some(File::open(s)?),
        None => None,
    };
    let out_file = match &c.out_file {
        Some(s) => Some(File::create(s)?),
        None => None,
    };
    let filesize = if let Some(f) = &in_file {
        Some(f.metadata()?.len() as usize)
    } else {
        None
    };

    let start = Instant::now();
    match c.direction {
        Direction::Encrypt => {
            match encrypt(&mut in_file.unwrap(), &mut out_file.unwrap(),&c.password, &c.ui, filesize, c.algorithm) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file)?;
                    }
                    return Err(e)
                }
            };
        }
        Direction::Decrypt => {
            match decrypt(&mut in_file.unwrap(), &mut out_file.unwrap(),&c.password, &c.ui, filesize) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file)?;
                    }
                    return Err(e)
                }
            };
        }
    }
    let duration = start.elapsed().as_secs_f64();
    Ok(duration)
}

