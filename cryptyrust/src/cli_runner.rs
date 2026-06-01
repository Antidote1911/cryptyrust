use arsenic::{
    arsenic_find_matching_key, arsenic_main_routine, arsenic_main_routine_with_key,
    arsenic_rekey, is_arsenic_file,
    keystore::{load_identity_file, load_keystore, resolve_recipient, keys_dir, save_key, KeyEntry, serialize_identity, parse_identity},
    encode_pubkey,
    ArsenicParams, Direction, Secret, Ui,
    bench_cipher_combinations, best_combination, CipherId,
};
use clap::Parser;
use crate::cli::{Cli, KeygenCli};
use std::{
    env,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};
use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};

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
                .unwrap_or_else(|_| ProgressStyle::default_bar())
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
                .unwrap_or_else(|_| ProgressStyle::default_bar())
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

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run() {
    // Dispatch `cryptyrust keygen [...]` before the main clap parser so the
    // existing required-mode group does not interfere.
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(|s| s.as_str()) == Some("keygen") {
        // Prepend "cryptyrust keygen" as argv[0] so clap shows the right usage line.
        let argv: Vec<String> = std::iter::once("cryptyrust keygen".to_string())
            .chain(raw.into_iter().skip(2))
            .collect();
        let cli = KeygenCli::parse_from(argv);
        if let Err(e) = run_keygen(cli) {
            eprintln!("\n{e}");
            std::process::exit(1);
        }
        return;
    }

    let app = Cli::parse();

    if app.bench() {
        run_bench();
        return;
    }

    if app.rekey().is_some() {
        match run_rekey(&app) {
            Ok(path) => println!("\nSuccess! Password changed for {path}"),
            Err(e) => { eprintln!("\n{e}"); std::process::exit(1); }
        }
    } else {
        match run_crypt(&app) {
            Ok((output_filename, mode, time)) => {
                let m = match mode {
                    Direction::Encrypt => "encrypted",
                    Direction::Decrypt => "decrypted",
                };
                if let Some(name) = output_filename {
                    println!("\nSuccess! {name} has been {m} in {time:.2} s");
                }
            }
            Err(e) => { eprintln!("\n{e}"); std::process::exit(1); }
        }
    }
}

// ── Rekey ─────────────────────────────────────────────────────────────────────

fn run_rekey(app: &Cli) -> Result<String> {
    let f = app.rekey().unwrap();
    let path = Path::new(f);
    if !(path.exists() && path.is_file()) {
        return Err(anyhow!("Invalid filename: {f}"));
    }
    if !is_arsenic_file(path) {
        return Err(anyhow!("{f} is not a valid Arsenic (.arsn) file"));
    }
    let old_password = Secret::new(
        rpassword::prompt_password("Current password: ")
            .context("could not read current password")?,
    );
    let new_password = Secret::new(
        rpassword::prompt_password("New password (minimum 8 characters): ")
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
    arsenic_rekey(path, &old_password, &new_password, &RekeyProgress::new())
        .map_err(|e| anyhow!(e))?;
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
        let f = app.encrypt().unwrap();
        let p = Path::new(f);
        if !(p.exists() && p.is_file()) {
            return Err(anyhow!("Invalid filename: {f}"));
        }
        Some(f)
    } else {
        let f = app.decrypt().unwrap();
        let p = Path::new(f);
        if !(p.exists() && p.is_file()) {
            return Err(anyhow!("Invalid filename: {f}"));
        }
        Some(f)
    };

    let output_path = generate_output_path(&direction, filename, app.output())
        .unwrap()
        .to_str()
        .ok_or_else(|| anyhow!("could not convert output path to string"))?
        .to_string();

    let out_str = output_path.as_str();
    let ui = Box::new(ProgressUpdater::new(direction.clone()));

    let duration = match direction {
        Direction::Encrypt => run_encrypt(app, filename, out_str, ui)?,
        Direction::Decrypt => run_decrypt(app, filename.unwrap(), out_str, ui)?,
    };

    Ok((Some(output_path), direction, duration))
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

fn run_encrypt(
    app: &Cli,
    filename: Option<&str>,
    out_str: &str,
    ui: Box<ProgressUpdater>,
) -> Result<f64> {
    let mut recipients: Vec<arsenic::HybridRecipient> = Vec::new();
    for spec in app.recipients() {
        match resolve_recipient(spec) {
            Some(r) => recipients.push(r),
            None => return Err(anyhow!(
                "cannot resolve recipient '{spec}': not a contact name or key file with hybrid key"
            )),
        }
    }

    let password: Secret<String> = if !recipients.is_empty()
        && app.password().is_none()
        && app.passwordfile().is_none()
    {
        let r = arsenic::random_bytes_32();
        Secret::new(r.iter().map(|b| format!("{b:02x}")).collect())
    } else {
        get_password_for_encrypt(app)?
    };

    let params = ArsenicParams {
        hdr_cipher: app.hdr_cipher(),
        pld_cipher: app.pld_cipher(),
        recipients,
        ..ArsenicParams::from(app.strength())
    };

    arsenic_main_routine(
        &Direction::Encrypt,
        filename,
        Some(out_str),
        &password,
        ui,
        Some(params),
    )
    .map_err(|e| anyhow!(e))
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

fn run_decrypt(
    app: &Cli,
    filename: &str,
    out_str: &str,
    ui: Box<ProgressUpdater>,
) -> Result<f64> {
    let path = Path::new(filename);

    let explicit_identities: Vec<_> = app
        .identities()
        .iter()
        .filter_map(|p| load_identity_file(Path::new(p)))
        .collect();

    if !explicit_identities.is_empty() {
        let privkeys: Vec<[u8; 32]> = explicit_identities.iter().map(|k| k.private_key).collect();
        if let Some(idx) = arsenic_find_matching_key(path, &privkeys) {
            eprintln!("Decrypting with identity: {}", explicit_identities[idx].name);
            return arsenic_main_routine_with_key(
                Some(filename),
                Some(out_str),
                &Secret::new(privkeys[idx]),
                ui,
            )
            .map_err(|e| anyhow!(e));
        }
        return Err(anyhow!("none of the provided identity files can decrypt this file"));
    } else {
        let keystore = load_keystore();
        if !keystore.is_empty() {
            let privkeys: Vec<[u8; 32]> = keystore.iter().map(|k| k.private_key).collect();
            if let Some(idx) = arsenic_find_matching_key(path, &privkeys) {
                eprintln!("Decrypting with stored key: {}", keystore[idx].name);
                return arsenic_main_routine_with_key(
                    Some(filename),
                    Some(out_str),
                    &Secret::new(privkeys[idx]),
                    ui,
                )
                .map_err(|e| anyhow!(e));
            }
        }
    }

    let password = get_password_for_decrypt(app)?;
    arsenic_main_routine(
        &Direction::Decrypt,
        Some(filename),
        Some(out_str),
        &password,
        ui,
        None,
    )
    .map_err(|e| anyhow!(e))
}

// ── Password helpers ──────────────────────────────────────────────────────────

fn get_password_for_encrypt(app: &Cli) -> Result<Secret<String>> {
    if let Some(p) = app.password() {
        return Ok(Secret::new(p));
    }
    if let Some(f) = app.passwordfile() {
        let s = std::fs::read_to_string(f)
            .with_context(|| format!("cannot read password file: {f}"))?;
        return Ok(Secret::new(s));
    }
    let pw = rpassword::prompt_password("Password (minimum 8 characters): ")
        .context("could not read password")?;
    if pw.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("could not confirm password")?;
    if pw != confirm {
        return Err(anyhow!("passwords do not match"));
    }
    Ok(Secret::new(pw))
}

fn get_password_for_decrypt(app: &Cli) -> Result<Secret<String>> {
    if let Some(p) = app.password() {
        return Ok(Secret::new(p));
    }
    if let Some(f) = app.passwordfile() {
        let s = std::fs::read_to_string(f)
            .with_context(|| format!("cannot read password file: {f}"))?;
        return Ok(Secret::new(s));
    }
    let pw = rpassword::prompt_password("Password: ").context("could not read password")?;
    Ok(Secret::new(pw))
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
            Err(format!("Error: file {p:?} already exists."))
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
            format!("{base}{ARSENIC_EXTENSION}")
        }
        Direction::Decrypt => {
            let name = name.unwrap_or("stdin");
            if name.ends_with(ARSENIC_EXTENSION) {
                name.strip_suffix(ARSENIC_EXTENSION).unwrap().to_string()
            } else {
                prepend("decrypted_".to_string(), name)
                    .ok_or_else(|| format!("could not prepend decrypted_ to {name}"))?
            }
        }
    };
    path.push(f);
    find_filename(path).ok_or_else(|| "could not generate filename".to_string())
}

fn find_filename(path: PathBuf) -> Option<PathBuf> {
    let mut i = 1;
    let mut path = path;
    let backup = path.clone();
    while path.exists() {
        path = backup.clone();
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ext  = path.extension().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let parent = path.parent()?;
        let new_file = if ext.is_empty() {
            format!("{stem} ({i})")
        } else {
            format!("{stem} ({i}).{ext}")
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
    path = [parent, Path::new(&format!("{}{}", prefix, file.to_string_lossy()))].iter().collect();
    Some(path.to_string_lossy().to_string())
}

// ── Cipher benchmark ──────────────────────────────────────────────────────────

fn run_bench() {
    const PAYLOAD_MIB: usize = 32;
    println!("Benchmarking 3 AEAD ciphers on {PAYLOAD_MIB} MiB...\n");

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}%")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-"),
    );

    struct BenchUi(ProgressBar);
    impl Ui for BenchUi {
        fn output(&self, pct: i32) {
            self.0.set_position(pct as u64);
            if pct >= 10 { self.0.set_message("Testing ciphers..."); }
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
            cipher_name(r.cipher), r.encrypt_mibps, r.decrypt_mibps, tag
        );
    }
    let (hdr, pld) = best_combination(&results);
    println!("\n  Fastest:  --hdr-cipher {}  --pld-cipher {}\n", cipher_arg(hdr), cipher_arg(pld));
}

fn cipher_name(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256       => "Deoxys-II-256",
        CipherId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        CipherId::Aes256GcmSiv      => "AES-256-GCM-SIV",
    }
}

fn cipher_arg(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256       => "deoxys-ii",
        CipherId::XChaCha20Poly1305 => "xchacha20",
        CipherId::Aes256GcmSiv      => "aes-gcm-siv",
    }
}

// ── Key management ────────────────────────────────────────────────────────────

fn run_keygen(cli: KeygenCli) -> Result<()> {
    if cli.list {
        return keygen_list();
    }
    if !cli.to_public.is_empty() {
        return keygen_to_public(&cli.to_public);
    }
    keygen_generate(cli)
}

fn keygen_list() -> Result<()> {
    let keys = load_keystore();
    if keys.is_empty() {
        let dir = keys_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".into());
        println!("No keypairs found in keystore ({dir}).");
        return Ok(());
    }
    println!("{:<20} {}", "Name", "Public key");
    println!("{}", "─".repeat(80));
    for key in &keys {
        println!("{:<20} {}", key.name, encode_pubkey(&key.public_key));
    }
    Ok(())
}

fn keygen_generate(cli: KeygenCli) -> Result<()> {
    if cli.store && cli.name.is_empty() {
        return Err(anyhow!("--name is required when using --store"));
    }

    let mut entry = KeyEntry::generate(cli.name.clone());
    let pub_enc = encode_pubkey(&entry.public_key);

    if cli.store {
        save_key(&mut entry).map_err(|e| anyhow!(e))?;
        let path = entry.file_path.as_ref().unwrap();
        eprintln!("Identity written to: {}", path.display());
        eprintln!("Public key: {pub_enc}");
    } else if let Some(path) = &cli.output {
        let content = serialize_identity(&entry);
        write_identity_file(path, &content)
            .with_context(|| format!("cannot write to {}", path.display()))?;
        eprintln!("Identity written to: {}", path.display());
        eprintln!("Public key: {pub_enc}");
    } else {
        let content = serialize_identity(&entry);
        print!("{content}");
        eprintln!("Public key: {pub_enc}");
    }

    Ok(())
}

fn keygen_to_public(sources: &[String]) -> Result<()> {
    for source in sources {
        let content = if source == "-" {
            let stdin = io::stdin();
            stdin.lock().lines().collect::<io::Result<Vec<_>>>()?.join("\n")
        } else {
            std::fs::read_to_string(source)
                .with_context(|| format!("cannot read {source}"))?
        };
        let path = PathBuf::from(source);
        let entry = parse_identity(&content, path)
            .ok_or_else(|| anyhow!("no valid private key found in {source}"))?;
        println!("{}", encode_pubkey(&entry.public_key));
    }
    Ok(())
}

#[cfg(unix)]
fn write_identity_file(path: &Path, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_identity_file(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("{} already exists", path.display()));
    }
    std::fs::write(path, content)?;
    Ok(())
}
