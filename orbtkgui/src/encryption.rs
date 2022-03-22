use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use cryptyrust_core::*;
use std::io::Read;

const FILE_EXTENSION: &str = ".crypty";
const SIGNATURE: [u8; 4] = [0xC1, 0x0A, 0x6B, 0xED];

struct ProgressUpdater {}

impl cryptyrust_core::Ui for ProgressUpdater {
	fn output(&self, _percentage: i32) {}
}


#[derive(Debug)]
pub enum FileType {
	Encrypted,
	Decrypted,
}

pub fn get_file_type(path: &String) -> FileType {

	// start reading stream before handing to encrypt/decrypt
	let mut file = std::fs::File::open(&path).unwrap();
	let mut first_four = [0u8; 4];

	file.read_exact(&mut first_four).unwrap();
	if first_four==SIGNATURE{
		return FileType::Encrypted;

	} else{
		return FileType::Decrypted;
	}
}

pub fn encrypt_file(path: &String, password: &String) -> Result<(), Box<dyn Error>> {

	// generate default filename and put in the current working directory
	let cwd = env::current_dir()?;
	let test=generate_default_filename(&cryptyrust_core::Mode::Encrypt, cwd, Some(path))?;
	let out_file = test.to_str().unwrap().to_string();

	let config = cryptyrust_core::Config::new(
		&cryptyrust_core::Mode::Encrypt,
		password.to_string(),
		Some(path.to_string()),
		Some(out_file.clone()),
		Box::new(ProgressUpdater {}),
	);
	cryptyrust_core::main_routine(&config)?;
	Ok(())
}

pub fn decrypt_file(path: &String, password: &String) -> Result<(), Box<dyn Error>> {

	// generate default filename and put in the current working directory
	let cwd = env::current_dir().map_err(|e| e.to_string())?;
	let test=generate_default_filename(&cryptyrust_core::Mode::Decrypt, cwd, Some(path))?;
	let out_file = test.to_str().unwrap().to_string();

	let config = cryptyrust_core::Config::new(
		&cryptyrust_core::Mode::Decrypt,
		password.to_string(),
		Some(path.to_string()),
		Some(out_file.clone()),
		Box::new(ProgressUpdater {}),
	);
	cryptyrust_core::main_routine(&config).map_err(|e| e.to_string())?;
	Ok(())
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
