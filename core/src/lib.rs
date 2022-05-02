mod errors;
mod crypto;
mod constants;
mod keygen;
mod config;

pub use crate::errors::CoreErr;
pub use crate::constants::*;
pub use crate::config::*;
pub use crate::crypto::*;

use std::fs::{remove_file, File};
use std::io::prelude::*;
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

    let mut input = file_or_stdin(in_file);
    let mut output = file_or_stdout(out_file);
    let start = Instant::now();
    match c.mode {
        Mode::Encrypt => {
            match crate::encrypt(&mut input, &mut output,&c.password, &c.ui, filesize) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file).map_err( |e2|CoreErr::DeleteFail(e.to_string(),e2.to_string()))?;
                    }
                    return Err(errors::CoreErr::DecryptionError)
                }
            };
        }
        Mode::Decrypt => {
            match crate::decrypt(&mut input, &mut output,&c.password, &c.ui, filesize) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file).map_err( |e2|CoreErr::DeleteFail(e.to_string(),e2.to_string()))?;
                    }
                    return Err(e)
                }
            };
        }
    }
    let duration = start.elapsed().as_secs_f64();
    Ok(duration)
}

fn file_or_stdin(reader: Option<File>) -> Box<dyn Read> {
    match reader {
        Some(file) => Box::new(file),
        None => Box::new(std::io::stdin()),
    }
}

fn file_or_stdout(writer: Option<File>) -> Box<dyn Write> {
    match writer {
        Some(file) => Box::new(file),
        None => Box::new(std::io::stdout()),
    }
}
