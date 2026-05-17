use cryptyrust_core::*;
mod cli;
use cli::{Cli};
use clap::{Parser};
use std::{
    path::{Path, PathBuf},
    env, process::exit};

use anyhow::anyhow;
use anyhow::Result;
use std::result::Result::Ok;

const FILE_EXTENSION: &str = ".crypty";

struct ProgressUpdater {
    mode: Direction,
}

impl Ui for ProgressUpdater {
    fn output(&self, _percentage: i32) {
            let _s = match self.mode {
                Direction::Encrypt => "Encrypting",
                Direction::Decrypt => "Decrypting",
            };
            //print!("\r{}: {}%", s, percentage);
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
        Err(e) => eprintln!("\n{}", e),
    };
}

fn run() -> Result<(Option<String>, Direction, f64)> {
    // Augment built args with derived args
    let app = Cli::parse();
    let direction = if app.encrypt().is_some() {
        Direction::Encrypt
    } else {
        Direction::Decrypt
    };

    let filename = if app.encrypt().is_some() {
        let f = app.encrypt().ok_or("file to encrypt not given").unwrap();
        // make sure input file exists
        let p = Path::new(&f);
        if !(p.exists() && p.is_file()) {
            println!("Invalid filename: {}", f);
            exit(1);
        }
        Some(f)
    } else if app.decrypt().is_some() {
        let f = app.decrypt().ok_or("file to decrypt not given").unwrap();
        let p = Path::new(&f);
        if !(p.exists() && p.is_file()) {
            println!("Invalid filename: {}", f);
            exit(1);
        }
        Some(f)
    } else {
        None // using stdin
    };

    let output_path =  {
        let s = generate_output_path(&direction, filename.as_deref(), app.output()).unwrap()
            .to_str()
            .ok_or("could not convert output path to string").unwrap()
            .to_string();
        Some(s)

    };

    // get_password needs to only happen if using neither stdin nor stdout: using requires() in clap
    // password prompting is affected by both stdin and stdout, whereas other printing is affected only by stdout
    let password: Secret<String>= if app.password().is_some() {
        let tmp=app.password().unwrap();
        Secret::new(tmp)
    } else if app.passwordfile().is_some() {
        let pw_file = app.passwordfile().unwrap();
        let p = Path::new(&pw_file);
        drop(pw_file.to_string());
        let tmp=std::fs::read_to_string(p).unwrap();
        Secret::new(tmp)
    } else {
        get_password(&direction)
    };
    let ui = Box::new(ProgressUpdater {
        mode: direction.clone(),
    });

    let config = Config::new(
        direction.clone(),
        app.algo(),
        app.strength(),
        password,
        filename.map(|f| f.to_string()),
        output_path.clone(),
        ui,
        app.hash(),
        app.bench());

    match main_routine(&config) {
        Ok(duration) =>{ Ok((output_path, direction, duration))},
        Err(e) => {
            return Err(anyhow!(e))
        }
    }
}

fn get_password(mode: &Direction) -> Secret<String> {
    match mode {
        Direction::Encrypt => {
            let password = rpassword::prompt_password(
                "Password (minimum 8 characters, longer is better): ",
            )
            .expect("could not get password from user");
            if password.len() < 8 {
                println!("Error: password must be at least 8 characters. Exiting.");
                exit(12);
            }
            let verified_password = rpassword::prompt_password("Confirm password: ")
                .expect("could not get password from user");
            if password != verified_password {
                println!("Error: passwords do not match. Exiting.");
                exit(1);
            }
            Secret::new(password)
        }
        Direction::Decrypt => {
            let password= rpassword::prompt_password("Password: ").expect("could not get password from user");
            Secret::new(password)
        },
    }
}

fn generate_output_path(
    mode: &Direction,
    input: Option<&str>,
    output: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(..) = output {
        // if output flag was specified,
        let p = PathBuf::from(output.unwrap());
        if p.exists() && p.is_dir() {
            // and it's a directory,
            generate_default_filename(mode, p, input) // give it a default filename.
        } else if p.exists() && p.is_file() {
            Err(format!("Error: file {:?} already exists. Must choose new filename or specify directory to generate default filename.", p))
        } else {
            // otherwise use it as the output filename.
            Ok(p)
        }
    } else {
        // if output not specified, generate default filename and put in the current working directory
        let cwd = env::current_dir().map_err(|e| e.to_string())?;
        generate_default_filename(mode, cwd, input)
    }
}

fn generate_default_filename(
    mode: &Direction,
    _path: PathBuf,
    name: Option<&str>,
) -> Result<PathBuf, String> {
    let mut path = _path;
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
            let name = if let Some(n) = name { n } else { "stdin" };
            if name.ends_with(FILE_EXTENSION) {
                name[..name.len() - FILE_EXTENSION.len()].to_string()
            } else {
                prepend("decrypted_".to_string(), name)
                    .ok_or(format!("could not prepend decrypted_ to filename {}", name))?
            }
        }
    };
    path.push(f);
    find_filename(path).ok_or_else(|| "could not generate filename".to_string())
}

fn find_filename(_path: PathBuf) -> Option<PathBuf> {
    let mut i = 1;
    let mut path = _path;
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
