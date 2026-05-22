use cryptyrust_core::*;
mod cli;
use clap::Parser;
use cli::Cli;
use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::result::Result::Ok;

const FILE_EXTENSION: &str = ".crypty";

struct ProgressUpdater {
    mode: Direction,
    pb: ProgressBar,
}

impl ProgressUpdater {
    fn new(mode: Direction) -> Self {
        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}%")
                .unwrap()
                .progress_chars("#>-"),
        );
        Self { mode, pb }
    }
}

impl Ui for ProgressUpdater {
    fn output(&self, percentage: i32) {
        self.pb.set_position(percentage as u64);
        if percentage >= 100 {
            let msg = match self.mode {
                Direction::Encrypt => "Encrypted",
                Direction::Decrypt => "Decrypted",
            };
            self.pb.finish_with_message(msg);
        }
    }
}

fn main() {
    match run() {
        Ok((output_filename, mode, time)) => {
            let m = match mode {
                Direction::Encrypt => "encrypted",
                Direction::Decrypt => "decrypted",
            };
            if let Some(name) = output_filename {
                println!("\nSuccess! {} has been {} in {} s", name, m, time);
            }
        }
        Err(e) => {
            eprintln!("\n{}", e);
            std::process::exit(1);
        }
    };
}

fn run() -> Result<(Option<String>, Direction, f64)> {
    let app = Cli::parse();
    let direction = if app.encrypt().is_some() {
        Direction::Encrypt
    } else {
        Direction::Decrypt
    };

    let filename = if app.encrypt().is_some() {
        let f = app.encrypt().ok_or("file to encrypt not given").unwrap();
        let p = Path::new(&f);
        if !(p.exists() && p.is_file()) {
            return Err(anyhow!("Invalid filename: {}", f));
        }
        Some(f)
    } else if app.decrypt().is_some() {
        let f = app.decrypt().ok_or("file to decrypt not given").unwrap();
        let p = Path::new(&f);
        if !(p.exists() && p.is_file()) {
            return Err(anyhow!("Invalid filename: {}", f));
        }
        Some(f)
    } else {
        None
    };

    let output_path = {
        let s = generate_output_path(&direction, filename, app.output())
            .unwrap()
            .to_str()
            .ok_or("could not convert output path to string")
            .unwrap()
            .to_string();
        Some(s)
    };

    let password: Secret<String> = if app.password().is_some() {
        Secret::new(app.password().unwrap())
    } else if app.passwordfile().is_some() {
        let pw_file = app.passwordfile().unwrap();
        let p = Path::new(&pw_file);
        let tmp = std::fs::read_to_string(p)
            .with_context(|| format!("could not read password file: {}", pw_file))?;
        Secret::new(tmp)
    } else {
        get_password(&direction)?
    };

    let ui = Box::new(ProgressUpdater::new(direction.clone()));

    let config = Config::new(
        direction.clone(),
        app.algo(),
        app.strength(),
        password,
        filename.map(|f| f.to_string()),
        output_path.clone(),
        ui,
        app.hash(),
        app.bench(),
    );

    match main_routine(&config) {
        Ok(duration) => Ok((output_path, direction, duration)),
        Err(e) => Err(anyhow!(e)),
    }
}

fn get_password(mode: &Direction) -> Result<Secret<String>> {
    match mode {
        Direction::Encrypt => {
            let password =
                rpassword::prompt_password("Password (minimum 8 characters, longer is better): ")
                    .context("could not get password from user")?;
            if password.len() < 8 {
                return Err(anyhow!("password must be at least 8 characters"));
            }
            let verified_password = rpassword::prompt_password("Confirm password: ")
                .context("could not get password from user")?;
            if password != verified_password {
                return Err(anyhow!("passwords do not match"));
            }
            Ok(Secret::new(password))
        }
        Direction::Decrypt => {
            let password = rpassword::prompt_password("Password: ")
                .context("could not get password from user")?;
            Ok(Secret::new(password))
        }
    }
}

fn generate_output_path(
    mode: &Direction,
    input: Option<&str>,
    output: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(output) = output {
        let p = PathBuf::from(output);
        if p.exists() && p.is_dir() {
            generate_default_filename(mode, p, input)
        } else if p.exists() && p.is_file() {
            Err(format!("Error: file {:?} already exists. Must choose new filename or specify directory to generate default filename.", p))
        } else {
            Ok(p)
        }
    } else {
        let cwd = env::current_dir().map_err(|e| e.to_string())?;
        generate_default_filename(mode, cwd, input)
    }
}

fn generate_default_filename(
    mode: &Direction,
    path: PathBuf,
    name: Option<&str>,
) -> Result<PathBuf, String> {
    let mut path = path;
    let f = match mode {
        Direction::Encrypt => {
            let mut with_ext = if let Some(n) = name {
                n.to_string()
            } else {
                "encrypted".to_string()
            };
            with_ext.push_str(FILE_EXTENSION);
            with_ext
        }
        Direction::Decrypt => {
            let name = name.unwrap_or("stdin");
            if name.ends_with(FILE_EXTENSION) {
                name.strip_suffix(FILE_EXTENSION).unwrap().to_string()
            } else {
                prepend("decrypted_".to_string(), name)
                    .ok_or(format!("could not prepend decrypted_ to filename {}", name))?
            }
        }
    };
    path.push(f);
    find_filename(path).ok_or_else(|| "could not generate filename".to_string())
}

fn find_filename(path: PathBuf) -> Option<PathBuf> {
    let mut i = 1;
    let mut path = path;
    let backup_path = path.clone();
    while path.exists() {
        path = backup_path.clone();
        let stem = match path.file_stem() {
            Some(s) => s.to_string_lossy().to_string(),
            None => "".to_string(),
        };
        let ext = match path.extension() {
            Some(s) => s.to_string_lossy().to_string(),
            None => "".to_string(),
        };
        let parent = path.parent()?;
        let new_file = match ext.as_str() {
            "" => format!("{} ({})", stem, i),
            _ => format!("{} ({}).{}", stem, i, ext),
        };
        path = [parent, Path::new(&new_file)].iter().collect();
        i += 1;
    }
    Some(path)
}

fn prepend(prefix: String, p: &str) -> Option<String> {
    let mut path = PathBuf::from(p);
    let file = path.file_name()?;
    let parent = path.parent()?;
    path = [
        parent,
        Path::new(&format!("{}{}", prefix, file.to_string_lossy())),
    ]
    .iter()
    .collect();
    Some(path.to_string_lossy().to_string())
}
