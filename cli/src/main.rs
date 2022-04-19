use cryptyrust_core::*;
mod cli;
use clap::{crate_name, Args, Command};
use cli::Cli;

use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
    process::exit,
};

const FILE_EXTENSION: &str = ".crypty";

struct ProgressUpdater {
    mode: Mode,
}

impl Ui for ProgressUpdater {
    fn output(&self, percentage: i32) {
        let s = match self.mode {
            Mode::Encrypt => "Encrypting",
            Mode::Decrypt => "Decrypting",
        };
        print!("\r{}: {}%", s, percentage);
    }
}

fn main() {
    match run() {
        Ok((output_filename, mode)) => {
            let m = match mode {
                Mode::Encrypt => "encrypted",
                Mode::Decrypt => "decrypted",
            };
            if let Some(name) = output_filename {
                println!("\nSuccess! {} has been {}.", name, m);
            }
        }
        Err(e) => eprintln!("\n{}", e),
    };
}

fn run() -> Result<(Option<String>, Mode), Box<dyn Error>> {
    let cli = Command::new(crate_name!());
    // Augment built args with derived args
    let cli = Cli::augment_args(cli);
    let matches = cli.get_matches();

    let mode = if matches.is_present("encrypt") {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };

    let filename = if matches.is_present("encrypt") {
        let f = matches
            .value_of("encrypt")
            .ok_or("file to encrypt not given")?;
        // make sure input file exists
        let p = Path::new(f);
        if !(p.exists() && p.is_file()) {
            println!("Invalid filename: {}", f);
            exit(1);
        }
        Some(f)
    } else if matches.is_present("decrypt") {
        let f = matches
            .value_of("decrypt")
            .ok_or("file to decrypt not given")?;
        let p = Path::new(f);
        if !(p.exists() && p.is_file()) {
            println!("Invalid filename: {}", f);
            exit(1);
        }
        Some(f)
    } else {
        None // using stdin
    };

    let output_path = generate_output_path(&mode, filename, matches.value_of("output"))?
        .to_str()
        .ok_or("could not convert output path to string")?
        .to_string();

    // get_password needs to only happen if using neither stdin nor stdout: using requires() in clap
    // password prompting is affected by both stdin and stdout, whereas other printing is affected only by stdout
    let password = if matches.is_present("password") {
        matches
            .value_of("password")
            .ok_or("couldn't get password value")?
            .to_string()
    } else if matches.is_present("passwordfile") {
        let pw_file = matches
            .value_of("passwordfile")
            .ok_or("could not get value of password file")?
            .to_string();
        let p = Path::new(&pw_file);
        std::fs::read_to_string(p).map_err(|e| format!("could not read password file: {}", e))?
    } else {
        get_password(&mode)
    };
    let ui = Box::new(ProgressUpdater { mode: mode.clone() });
    let config = Config::new(
        &mode,
        password,
        filename.map(|f| f.to_string()),
        Option::from(output_path.clone()),
        ui,
    );
    match main_routine(&config) {
        Ok(()) => Ok((Option::from(output_path), mode)),
        Err(e) => Err(e),
    }
}

fn get_password(mode: &Mode) -> String {
    match mode {
        Mode::Encrypt => {
            let password =
                rpassword::prompt_password("Password (minimum 8 characters, longer is better): ")
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
            password
        }
        Mode::Decrypt => {
            rpassword::prompt_password("Password: ").expect("could not get password from user")
        }
    }
}

fn generate_output_path(
    mode: &Mode,
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
    mode: &Mode,
    _path: PathBuf,
    name: Option<&str>,
) -> Result<PathBuf, String> {
    let mut path = _path;
    let f = match mode {
        Mode::Encrypt => {
            let mut with_ext = if let Some(n) = name {
                n.to_string()
            } else {
                "encrypted".to_string()
            };
            with_ext.push_str(FILE_EXTENSION);
            with_ext
        }
        Mode::Decrypt => {
            let name = if let Some(n) = name { n } else { "stdin" };
            if name.ends_with(FILE_EXTENSION) {
                name[..name.len() - FILE_EXTENSION.len()].to_string()
            } else {
                prepend("decrypted_", name)
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

fn prepend(prefix: &str, p: &str) -> Option<String> {
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
