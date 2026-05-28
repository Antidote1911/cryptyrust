use cryptyrust_core::arsenic::ArsenicParams;
use cryptyrust_core::*;
mod cli;
use clap::Parser;
use cli::Cli;
use std::{
    env,
    path::{Path, PathBuf},
};

use cryptyrust_core::{bench_cipher_combinations, best_combination, CipherId};

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::result::Result::Ok;

const ARSENIC_EXTENSION: &str = ".arsn";

// ── Progress UI ───────────────────────────────────────────────────────────────

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

struct RekeyProgress {
    pb: ProgressBar,
}

impl RekeyProgress {
    fn new() -> Self {
        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}%")
                .unwrap()
                .progress_chars("#>-"),
        );
        Self { pb }
    }
}

impl Ui for RekeyProgress {
    fn output(&self, percentage: i32) {
        self.pb.set_position(percentage as u64);
        if percentage >= 100 {
            self.pb.finish_with_message("Password changed");
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let app = Cli::parse();

    if app.bench() {
        run_bench();
        return;
    }

    if app.rekey().is_some() {
        match run_rekey(&app) {
            Ok(path) => println!("\nSuccess! Password changed for {}", path),
            Err(e) => {
                eprintln!("\n{}", e);
                std::process::exit(1);
            }
        }
    } else {
        match run_crypt(&app) {
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
        }
    }
}

// ── Rekey ─────────────────────────────────────────────────────────────────────

fn run_rekey(app: &Cli) -> Result<String> {
    let f = app.rekey().unwrap();
    let path = Path::new(f);

    if !(path.exists() && path.is_file()) {
        return Err(anyhow!("Invalid filename: {}", f));
    }
    if !is_arsenic_file(path) {
        return Err(anyhow!("{} is not a valid Arsenic V1 (.arsn) file", f));
    }

    let old_password = Secret::new(
        rpassword::prompt_password("Current password: ")
            .context("could not read current password")?,
    );
    let new_password = Secret::new(
        rpassword::prompt_password("New password (minimum 8 characters, longer is better): ")
            .context("could not read new password")?,
    );
    if new_password.expose().len() < 8 {
        return Err(anyhow!("new password must be at least 8 characters"));
    }
    let confirm = rpassword::prompt_password("Confirm new password: ")
        .context("could not read password confirmation")?;
    if new_password.expose() != &confirm {
        return Err(anyhow!("new passwords do not match"));
    }

    let ui = RekeyProgress::new();
    arsenic_rekey(path, &old_password, &new_password, &ui).map_err(|e| anyhow!(e))?;

    Ok(f.to_string())
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

fn run_crypt(app: &Cli) -> Result<(Option<String>, Direction, f64)> {
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

    let out_str = output_path.as_deref().unwrap();
    let ui = Box::new(ProgressUpdater::new(direction.clone()));
    let params = ArsenicParams {
        hdr_cipher: app.hdr_cipher(),
        pld_cipher: app.pld_cipher(),
        ..ArsenicParams::from(app.strength())
    };

    let duration = match arsenic_main_routine(
        &direction,
        filename,
        Some(out_str),
        &password,
        ui,
        Some(params),
    ) {
        Ok(d) => d,
        Err(e) => return Err(anyhow!(e)),
    };

    Ok((output_path, direction, duration))
}

// ── Password prompts ──────────────────────────────────────────────────────────

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

// ── Output path helpers ───────────────────────────────────────────────────────

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
            let base = name.unwrap_or("encrypted").to_string();
            format!("{}{}", base, ARSENIC_EXTENSION)
        }
        Direction::Decrypt => {
            let name = name.unwrap_or("stdin");
            if name.ends_with(ARSENIC_EXTENSION) {
                name.strip_suffix(ARSENIC_EXTENSION).unwrap().to_string()
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

// ── Cipher benchmark ──────────────────────────────────────────────────────────

fn run_bench() {
    const PAYLOAD_MIB: usize = 32;

    println!(
        "Benchmarking 3 AEAD ciphers on {} MiB (Interactive Argon2id key, single run)...\n",
        PAYLOAD_MIB
    );

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}%")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Argon2id key derivation...");

    struct BenchUi(ProgressBar);
    impl Ui for BenchUi {
        fn output(&self, pct: i32) {
            self.0.set_position(pct as u64);
            if pct >= 10 {
                self.0.set_message("Testing ciphers...");
            }
        }
    }

    let results = bench_cipher_combinations(PAYLOAD_MIB, &BenchUi(pb.clone()));
    pb.finish_and_clear();

    println!("  {:<22} {:>13} {:>13}", "Cipher", "Encrypt", "Decrypt");
    println!("  {}", "─".repeat(52));
    for (i, r) in results.iter().enumerate() {
        let tag = if i == 0 { "  ★ fastest" } else { "" };
        println!(
            "  {:<22} {:>9.0} MiB/s {:>9.0} MiB/s{}",
            cipher_display_name(r.cipher),
            r.encrypt_mibps,
            r.decrypt_mibps,
            tag,
        );
    }

    let (hdr, pld) = best_combination(&results);
    println!("\n  Fastest combination for this machine:");
    println!(
        "    --hdr-cipher {}  --pld-cipher {}\n",
        cipher_cli_arg(hdr),
        cipher_cli_arg(pld),
    );
}

fn cipher_display_name(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "Deoxys-II-256",
        CipherId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        CipherId::Aes256GcmSiv => "AES-256-GCM-SIV",
    }
}

fn cipher_cli_arg(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256 => "deoxys-ii",
        CipherId::XChaCha20Poly1305 => "xchacha20",
        CipherId::Aes256GcmSiv => "aes-gcm-siv",
    }
}
