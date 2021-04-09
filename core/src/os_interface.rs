
use std::error::Error;
use std::fs::{File, remove_file};
use std::io::prelude::*;
use sodiumoxide;

#[derive(Clone, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct Config {
    pub mode: Mode,
    pub password: String,
    pub filename: Option<String>,
    pub out_file: Option<String>,
    pub ui: Box<dyn Ui>,
}

pub trait Ui {
    fn output(&self, percentage: i32);
}

impl Config {
    pub fn new(_mode: &Mode, password: String, filename: Option<String>, out_file: Option<String>, ui: Box<dyn Ui>) -> Self {
        let mode: Mode = _mode.clone();
        Config{mode, password, filename, out_file, ui}
    }
}

pub fn main_routine(c: &Config) -> Result<(), Box<dyn Error>> {
    sodiumoxide::init().map_err(|_| "sodiumoxide init failed")?;
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
    match c.mode {
        Mode::Encrypt => {
            match crate::encrypt(&mut input, &mut output, &c.password, &c.ui, filesize) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file).map_err(|e2| format!("{}. Could not delete output file: {}.", e, e2))?;
                    }
                    Err(e)?
                },
            };
        },
        Mode::Decrypt => {
            // start reading stream before handing to encrypt/decrypt
            // legacy decrypt might need a first-four-bytes param
            let mut first_four = [0u8; 4];
            input.read_exact(&mut first_four)?;
            match first_four {
                crate::SIGNATURE => {
                    match crate::decrypt(&mut input, &mut output, &c.password, &c.ui, filesize) {
                        Ok(()) => (),
                        Err(e) => {
                            if let Some(out_file) = &c.out_file {
                                remove_file(&out_file).map_err(|e2| format!("{}. Could not delete output file: {}.", e, e2))?;
                            }
                            Err(e)?
                        },
                    };
                },
                _ => {
                    let first_four = if first_four != crate::legacy::SIGNATURE { Some(first_four) } else { None };
                    match crate::legacy::decrypt(&mut input, &mut output, &c.password, &c.ui, filesize, first_four) {
                        Ok(()) => (),
                        Err(e) => {
                            if let Some(out_file) = &c.out_file {
                                remove_file(&out_file).map_err(|e2| format!("{}. Could not delete output file: {}.", e, e2))?;
                            }
                            Err(e)?
                        },
                    };
                },
            }
        },
    }
    Ok(())
}

fn file_or_stdin(reader: Option<File>) -> Box<dyn Read> {
    match reader {
        Some(file) => Box::new(file),
        None => Box::new(std::io::stdin()),
    }
}

fn file_or_stdout(reader: Option<File>) -> Box<dyn Write> {
    match reader {
        Some(file) => Box::new(file),
        None => Box::new(std::io::stdout()),
    }
}
