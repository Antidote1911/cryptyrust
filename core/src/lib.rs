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
    let mut in_file =  File::open(&c.filename.as_ref().unwrap()).unwrap();

    let mut out_file = File::create(c.out_file.as_ref().unwrap()).unwrap();


    let filesize = in_file.metadata().unwrap().len() as u64;

    let start = Instant::now();
    match c.direction {
        Direction::Encrypt => {
            match encrypt(&mut in_file, &mut out_file,&c.password, &c.ui, filesize, c.algorithm,c.hashmode,c.benchmode) {
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
            match decrypt(&mut in_file, &mut out_file,&c.password, &c.ui, filesize,c.hashmode,c.benchmode) {
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

