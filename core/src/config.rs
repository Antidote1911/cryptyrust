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