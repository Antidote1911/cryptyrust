use std::error::Error;
use std::fs::remove_file;

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
    pub fn new(
        _mode: &Mode,
        password: String,
        filename: Option<String>,
        out_file: Option<String>,
        ui: Box<dyn Ui>,
    ) -> Self {
        let mode: Mode = _mode.clone();
        Config {
            mode,
            password,
            filename,
            out_file,
            ui,
        }
    }
}

pub fn main_routine(c: &Config) -> Result<(), Box<dyn Error>> {
    let in_file = c.filename.clone().unwrap();
    let out_file = c.out_file.clone().unwrap();

    match c.mode {
        Mode::Encrypt => {
            match crate::encrypt(&in_file, &out_file, &c.password, &c.ui) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file).map_err(|e2| {
                            format!("{}. Could not delete output file: {}.", e, e2)
                        })?;
                    }
                    return Err(e);
                }
            };
        }
        Mode::Decrypt => {
            match crate::decrypt(&in_file, &out_file, &c.password, &c.ui) {
                Ok(()) => (),
                Err(e) => {
                    if let Some(out_file) = &c.out_file {
                        remove_file(&out_file).map_err(|e2| {
                            format!("{}. Could not delete output file: {}.", e, e2)
                        })?;
                    }
                    return Err(e);
                }
            };
        }
    }
    Ok(())
}
