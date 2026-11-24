use arsenic::{
    arsenic_add_recipient_with_level, arsenic_find_matching_key, arsenic_find_slot_for_key,
    arsenic_list_recipients, arsenic_main_routine, arsenic_main_routine_with_key,
    arsenic_rekey, arsenic_remove_recipient, is_arsenic_file,
    arsenic_add_passphrase, arsenic_remove_passphrase, arsenic_list_passphrases,
    armor, dearmor,
    keystore::{
        load_identity_file, load_keystore, resolve_recipient, keys_dir, save_key, KeyEntry,
        serialize_identity, parse_identity,
    },
    encode_pubkey,
    ArsenicParams, Direction, Secret, Ui,
    bench_cipher_combinations, best_combination, CipherId,
    COMPRESSION_LEAKS_SIZE,
};
use clap::Parser;
use crate::file_utils::{check_new_password, cipher_label, is_armored_file};
use crate::cli::{
    Cli, KemLevelArg, KeygenCli, PassphraseAction, PassphraseCli, RecipientsAction, RecipientsCli,
};
use std::{
    env,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};
use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};

const ARSENIC_EXTENSION: &str = ".arsn";

/// Shown after a password is changed or removed: the file key stays the same,
/// so this is not a revocation.
const OLD_COPIES_NOTE: &str = "Note: copies of this file made earlier still open with the old password. \
     If that password is compromised, decrypt and re-encrypt to a new file.";
const ARMOR_EXTENSION: &str = ".arsn.armor";

// ── Progress UI ───────────────────────────────────────────────────────────────

fn progress_bar() -> ProgressBar {
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{wide_bar:.cyan/blue}] {pos}%")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-"),
    );
    pb
}

/// Progress bar that prints `done_message` when the operation reaches 100 %.
struct ProgressUpdater {
    done_message: &'static str,
    pb: ProgressBar,
}

impl ProgressUpdater {
    fn new(done_message: &'static str) -> Self {
        Self { done_message, pb: progress_bar() }
    }

    fn for_direction(mode: &Direction) -> Self {
        Self::new(match mode {
            Direction::Encrypt => "Encrypted",
            Direction::Decrypt => "Decrypted",
        })
    }
}

impl Ui for ProgressUpdater {
    fn output(&self, percentage: i32) {
        self.pb.set_position(u64::try_from(percentage).unwrap_or(0));
        if percentage >= 100 {
            self.pb.finish_with_message(self.done_message);
        }
    }
}

/// For header-only operations that finish instantly.
struct NoProgress;
impl Ui for NoProgress {
    fn output(&self, _: i32) {}
}

/// `path` must be an existing regular file.
fn require_file(path: &str) -> Result<&Path> {
    let p = Path::new(path);
    if p.is_file() {
        Ok(p)
    } else {
        Err(anyhow!("Invalid filename: {path}"))
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run() {
    // Dispatch `cryptyrust keygen [...]` before the main clap parser so the
    // existing required-mode group does not interfere.
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(std::string::String::as_str) == Some("keygen") {
        let argv: Vec<String> = std::iter::once("cryptyrust keygen".to_string())
            .chain(raw.into_iter().skip(2))
            .collect();
        let cli = KeygenCli::parse_from(argv);
        if let Err(e) = run_keygen(&cli) {
            eprintln!("\n{e}");
            std::process::exit(1);
        }
        return;
    }

    if raw.get(1).map(std::string::String::as_str) == Some("passphrase") {
        let argv: Vec<String> = std::iter::once("cryptyrust passphrase".to_string())
            .chain(raw.into_iter().skip(2))
            .collect();
        let cli = PassphraseCli::parse_from(argv);
        if let Err(e) = run_passphrase(cli) {
            eprintln!("\n{e}");
            std::process::exit(1);
        }
        return;
    }

    if raw.get(1).map(std::string::String::as_str) == Some("recipients") {
        let argv: Vec<String> = std::iter::once("cryptyrust recipients".to_string())
            .chain(raw.into_iter().skip(2))
            .collect();
        let cli = RecipientsCli::parse_from(argv);
        if let Err(e) = run_recipients(cli) {
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
            Ok(path) => {
                println!("\nSuccess! Password changed for {path}");
                println!("{OLD_COPIES_NOTE}");
            }
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
    let f = app.rekey().ok_or_else(|| anyhow!("no file given"))?;
    let path = require_file(f)?;
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
    check_new_password(new_password.expose()).map_err(|e| anyhow!(e))?;
    let confirm = rpassword::prompt_password("Confirm new password: ")
        .context("could not read password confirmation")?;
    if new_password.expose() != &confirm {
        return Err(anyhow!("new passwords do not match"));
    }
    arsenic_rekey(path, &old_password, &new_password, &ProgressUpdater::new("Password changed"))
        .map_err(|e| anyhow!(e))?;
    Ok(f.to_string())
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

fn run_crypt(app: &Cli) -> Result<(Option<String>, Direction, f64)> {
    let (direction, f) = match (app.encrypt(), app.decrypt()) {
        (Some(f), _) => (Direction::Encrypt, f),
        (None, Some(f)) => (Direction::Decrypt, f),
        (None, None) => return Err(anyhow!("no file given")),
    };
    require_file(f)?;
    let filename = Some(f);

    // With --armor the path computed here is the final armored file, so the
    // "already exists" / unique-name rules apply to what is really written.
    let armored = matches!(direction, Direction::Encrypt) && app.armor();
    let output_path = generate_output_path(&direction, filename, app.output(), armored)
        .map_err(|e| anyhow!(e))?
        .to_str()
        .ok_or_else(|| anyhow!("could not convert output path to string"))?
        .to_string();

    let out_str = output_path.as_str();
    let ui = Box::new(ProgressUpdater::for_direction(&direction));

    let duration = match direction {
        Direction::Encrypt => run_encrypt(app, filename, out_str, ui)?,
        Direction::Decrypt => run_decrypt(app, f, out_str, ui)?,
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
        // Recipients only: no password slot in the file.
        Secret::new(String::new())
    } else {
        get_password_for_encrypt(app)?
    };

    if let Some(level) = app.compress() {
        if !(1..=22).contains(&level) {
            return Err(anyhow!("--compress level must be 1–22 (got {level})"));
        }
        eprintln!("⚠  {COMPRESSION_LEAKS_SIZE}");
    }

    let params = ArsenicParams {
        hdr_cipher: app.hdr_cipher(),
        pld_cipher: app.pld_cipher(),
        recipients,
        kem_level: app.kem_level(),
        compress: app.compress(),
        ..ArsenicParams::from(app.strength())
    };

    if !app.armor() {
        return arsenic_main_routine(
            &Direction::Encrypt,
            filename,
            Some(out_str),
            &password,
            ui,
            Some(params),
        )
        .map_err(|e| anyhow!(e));
    }

    // --armor: encrypt to a temporary file next to the output, then write the
    // armored text to `out_str`. `create_new` guarantees an existing file is
    // never overwritten; the temporary file is removed on every exit path.
    let dir = match Path::new(out_str).parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".cryptyrust-")
        .suffix(".arsn.tmp")
        .tempfile_in(dir)
        .with_context(|| format!("cannot create temporary file in {}", dir.display()))?;
    let tmp_str = tmp
        .path()
        .to_str()
        .ok_or_else(|| anyhow!("could not convert temporary path to string"))?;
    let elapsed = arsenic_main_routine(
        &Direction::Encrypt,
        filename,
        Some(tmp_str),
        &password,
        ui,
        Some(params),
    )
    .map_err(|e| anyhow!(e))?;

    let ct = std::fs::read(tmp.path()).context("cannot read ciphertext for armoring")?;
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_str)
        .with_context(|| format!("cannot create armor file {out_str}"))?;
    if let Err(e) = out.write_all(armor(&ct).as_bytes()) {
        drop(out);
        let _ = std::fs::remove_file(out_str);
        return Err(anyhow!(e).context(format!("cannot write armor file {out_str}")));
    }

    Ok(elapsed)
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

fn run_decrypt(
    app: &Cli,
    filename: &str,
    out_str: &str,
    ui: Box<ProgressUpdater>,
) -> Result<f64> {
    // Auto-detect ASCII armor: if the file starts with the armor header, dearmor
    // to a memory buffer and decrypt from there.
    // Only the first bytes are read to decide: a binary file is streamed, never
    // loaded whole.
    if is_armored_file(Path::new(filename)) {
        let raw_bytes = std::fs::read(filename)
            .with_context(|| format!("cannot read {filename}"))?;
        let armor_str = std::str::from_utf8(&raw_bytes)
            .map_err(|_| anyhow!("armor file is not valid UTF-8"))?;
        let ct = dearmor(armor_str).map_err(|e| anyhow!("dearmor failed: {e}"))?;
        return decrypt_from_bytes(app, &ct, out_str, &ui);
    }

    let path = Path::new(filename);

    let explicit_identities: Vec<_> = app
        .identities()
        .iter()
        .filter_map(|p| load_identity_file(Path::new(p)))
        .collect();

    if explicit_identities.is_empty() {
        let keystore = load_keystore();
        if !keystore.is_empty() {
            if let Some(idx) = arsenic_find_matching_key(path, &keystore) {
                eprintln!("Decrypting with stored key: {}", keystore[idx].name);
                return arsenic_main_routine_with_key(
                    Some(filename), Some(out_str), &keystore[idx], ui,
                ).map_err(|e| anyhow!(e));
            }
        }
    } else {
        if let Some(idx) = arsenic_find_matching_key(path, &explicit_identities) {
            eprintln!("Decrypting with identity: {}", explicit_identities[idx].name);
            return arsenic_main_routine_with_key(
                Some(filename), Some(out_str), &explicit_identities[idx], ui,
            ).map_err(|e| anyhow!(e));
        }
        return Err(anyhow!("none of the provided identity files can decrypt this file"));
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
    // The minimum length applies however the new password is given.
    if app.password().is_some() || app.passwordfile().is_some() {
        let pw = get_password_for_decrypt(app)?;
        check_new_password(pw.expose()).map_err(|e| anyhow!(e))?;
        return Ok(pw);
    }
    let pw = rpassword::prompt_password("Password (minimum 8 characters): ")
        .context("could not read password")?;
    check_new_password(&pw).map_err(|e| anyhow!(e))?;
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("could not confirm password")?;
    if pw != confirm {
        return Err(anyhow!("passwords do not match"));
    }
    Ok(Secret::new(pw))
}

fn get_password_for_decrypt(app: &Cli) -> Result<Secret<String>> {
    resolve_password(app.password(), app.passwordfile().map(str::to_owned), "Password: ")
}

// ── Output path helpers ───────────────────────────────────────────────────────

fn generate_output_path(
    mode: &Direction,
    input: Option<&str>,
    output: Option<&str>,
    armored: bool,
) -> Result<PathBuf, String> {
    if let Some(output) = output {
        let p = PathBuf::from(output);
        if p.is_dir() {
            // Only the input's file name goes into the chosen directory: pushing
            // the whole input path would ignore `-o` for absolute inputs.
            let name = input
                .map(|i| {
                    Path::new(i)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .ok_or_else(|| format!("Invalid filename: {i}"))
                })
                .transpose()?;
            return generate_default_filename(mode, p, name.as_deref(), armored);
        }
        // Explicit file: with --armor the armored text goes to `<output>.armor`.
        let p = if armored {
            let mut s = p.into_os_string();
            s.push(".armor");
            PathBuf::from(s)
        } else {
            p
        };
        if p.exists() {
            Err(format!("Error: file \"{}\" already exists.", p.display()))
        } else {
            Ok(p)
        }
    } else {
        // No -o: the output lands next to the input (relative inputs resolve
        // against the current directory, absolute ones keep their directory).
        let cwd = env::current_dir().map_err(|e| e.to_string())?;
        generate_default_filename(mode, cwd, input, armored)
    }
}

fn generate_default_filename(
    mode: &Direction,
    path: PathBuf,
    name: Option<&str>,
    armored: bool,
) -> Result<PathBuf, String> {
    let mut path = path;
    let f = match mode {
        Direction::Encrypt => {
            let base = name.unwrap_or("encrypted").to_string();
            let ext = if armored { ARMOR_EXTENSION } else { ARSENIC_EXTENSION };
            format!("{base}{ext}")
        }
        Direction::Decrypt => {
            let name = name.unwrap_or("stdin");
            if let Some(stripped) = name
                .strip_suffix(ARMOR_EXTENSION)
                .or_else(|| name.strip_suffix(ARSENIC_EXTENSION))
            {
                stripped.to_string()
            } else {
                prepend("decrypted_", name)
                    .ok_or_else(|| format!("could not prepend decrypted_ to {name}"))?
            }
        }
    };
    path.push(f);
    find_filename(path).ok_or_else(|| "could not generate filename".to_string())
}

/// Return `path`, or the first free `name (N).ext` variant if it exists.
/// `.arsn.armor` is kept together as one extension.
fn find_filename(path: PathBuf) -> Option<PathBuf> {
    if !path.exists() {
        return Some(path);
    }
    let parent = path.parent()?.to_path_buf();
    let file = path.file_name()?.to_string_lossy().into_owned();
    // Length of the extension to keep after the counter, dot included.
    let ext_len = if file.ends_with(ARMOR_EXTENSION) {
        ARMOR_EXTENSION.len()
    } else {
        Path::new(&file).extension().map_or(0, |e| e.len() + 1)
    };
    let (stem, ext) = file.split_at(file.len() - ext_len);
    (1..u32::MAX).map(|i| parent.join(format!("{stem} ({i}){ext}"))).find(|p| !p.exists())
}

fn prepend(prefix: &str, p: &str) -> Option<String> {
    let mut path = PathBuf::from(p);
    let file = path.file_name()?;
    let parent = path.parent()?;
    path = [parent, Path::new(&format!("{}{}", prefix, file.to_string_lossy()))].iter().collect();
    Some(path.to_string_lossy().to_string())
}

// ── Cipher benchmark ──────────────────────────────────────────────────────────

fn run_bench() {
    const PAYLOAD_MIB: usize = 32;
    struct BenchUi(ProgressBar);
    impl Ui for BenchUi {
        fn output(&self, pct: i32) {
            self.0.set_position(u64::try_from(pct).unwrap_or(0));
            if pct >= 10 { self.0.set_message("Testing ciphers..."); }
        }
    }

    println!("Benchmarking 3 AEAD ciphers on {PAYLOAD_MIB} MiB...\n");
    let pb = progress_bar();
    let results = bench_cipher_combinations(PAYLOAD_MIB, &BenchUi(pb.clone()));
    pb.finish_and_clear();

    println!("  {:<22} {:>13} {:>13}", "Cipher", "Encrypt", "Decrypt");
    println!("  {}", "─".repeat(52));
    for (i, r) in results.iter().enumerate() {
        let tag = if i == 0 { "  ★ fastest" } else { "" };
        println!(
            "  {:<22} {:>9.0} MiB/s {:>9.0} MiB/s{}",
            cipher_label(r.cipher), r.encrypt_mibps, r.decrypt_mibps, tag
        );
    }
    let (hdr, pld) = best_combination(&results);
    println!("\n  Fastest:  --hdr-cipher {}  --pld-cipher {}\n", cipher_arg(hdr), cipher_arg(pld));
}

const fn cipher_arg(c: CipherId) -> &'static str {
    match c {
        CipherId::DeoxysII256       => "deoxys-ii",
        CipherId::XChaCha20Poly1305 => "xchacha20",
        CipherId::Aes256GcmSiv      => "aes-gcm-siv",
    }
}

// ── Key management ────────────────────────────────────────────────────────────

fn run_keygen(cli: &KeygenCli) -> Result<()> {
    if cli.list {
        keygen_list();
        return Ok(());
    }
    if !cli.to_public.is_empty() { return keygen_to_public(&cli.to_public); }
    keygen_generate(cli)
}

fn keygen_list() {
    let keys = load_keystore();
    if keys.is_empty() {
        let dir = keys_dir().map_or_else(|| "unknown".into(), |p| p.display().to_string());
        println!("No keypairs found in keystore ({dir}).");
        return;
    }
    println!("{:<20} Public key", "Name");
    println!("{}", "─".repeat(80));
    for key in &keys {
        println!("{:<20} {}", key.name, encode_pubkey(&key.public_key));
    }
}

fn keygen_generate(cli: &KeygenCli) -> Result<()> {
    if cli.kem_level.is_some() {
        eprintln!(
            "note: `keygen --kem-level` is ignored — a keypair works with both ML-KEM levels; \
             choose the level when encrypting (`-e FILE -R NAME --kem-level 1024`)."
        );
    }
    if cli.store && cli.name.is_empty() {
        return Err(anyhow!("--name is required when using --store"));
    }

    let mut entry = KeyEntry::generate(cli.name.clone());
    let pub_enc = encode_pubkey(&entry.public_key);

    if cli.store {
        save_key(&mut entry).map_err(|e| anyhow!(e))?;
        if let Some(path) = &entry.file_path {
            eprintln!("Identity written to: {}", path.display());
        }
    } else if let Some(path) = &cli.output {
        let content = serialize_identity(&entry);
        write_identity_file(path, &content)
            .with_context(|| format!("cannot write to {}", path.display()))?;
        eprintln!("Identity written to: {}", path.display());
    } else {
        let content = serialize_identity(&entry);
        print!("{content}");
    }
    eprintln!("Public key: {pub_enc}");

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

// ── Recipient management ──────────────────────────────────────────────────────

fn run_recipients(cli: RecipientsCli) -> Result<()> {
    match cli.action {
        RecipientsAction::List { file, identities } => recipients_list(&file, &identities),
        RecipientsAction::Add { file, recipient, password, passwordfile, kem_level } =>
            recipients_add(&file, &recipient, password, passwordfile.as_deref(), kem_level),
        RecipientsAction::Remove { file, identity, slot, password, passwordfile } =>
            recipients_remove(&file, identity.as_deref(), slot, password, passwordfile.as_deref()),
    }
}

/// List keyslots of `file`, probing the keystore + extra identity files to name them.
fn recipients_list(file: &str, extra_identities: &[String]) -> Result<()> {
    let path = Path::new(file);
    if !path.is_file() {
        return Err(anyhow!("File not found: {file}"));
    }

    let ephemeral_keys = arsenic_list_recipients(path).map_err(|e| anyhow!(e))?;
    let n = ephemeral_keys.len();

    println!("\nRecipients of '{file}' — {n} asymmetric keyslot(s):\n");

    if n == 0 {
        println!("  (no asymmetric keyslots — file is password-only)");
        return Ok(());
    }

    // Build a map: slot_index → key_name
    let mut slot_names: Vec<Option<String>> = vec![None; n];

    // Probe keystore keys first
    for entry in load_keystore() {
        if let Some(slot_idx) = arsenic_find_slot_for_key(path, &entry) {
            if slot_names[slot_idx].is_none() {
                slot_names[slot_idx] = Some(entry.name.clone());
            }
        }
    }

    // Probe extra identity files supplied via -i
    for id_path in extra_identities {
        if let Some(entry) = load_identity_file(Path::new(id_path)) {
            if let Some(slot_idx) = arsenic_find_slot_for_key(path, &entry) {
                if slot_names[slot_idx].is_none() {
                    let label = if entry.name.is_empty() { id_path.clone() } else { entry.name };
                    slot_names[slot_idx] = Some(label);
                }
            }
        }
    }

    for (i, (eph_key, name)) in ephemeral_keys.iter().zip(slot_names.iter()).enumerate() {
        let eph_enc = encode_pubkey(eph_key);
        match name {
            Some(n) => println!("  Slot {i:<3} {n:<20} [ephemeral: {eph_enc}]"),
            None    => println!("  Slot {i:<3} (unidentified)        [ephemeral: {eph_enc}]"),
        }
    }

    println!();
    println!("To remove a keyslot:");
    println!("  cryptyrust recipients remove {file} -i KEY_FILE -p PASSWORD");
    println!("  cryptyrust recipients remove {file} --slot N    -p PASSWORD");
    Ok(())
}

/// Add a recipient keyslot to an existing file.
fn recipients_add(
    file: &str,
    recipient_spec: &str,
    password: Option<String>,
    passwordfile: Option<&str>,
    kem_level: Option<KemLevelArg>,
) -> Result<()> {
    let path = Path::new(file);
    if !path.is_file() {
        return Err(anyhow!("File not found: {file}"));
    }
    if !is_arsenic_file(path) {
        return Err(anyhow!("{file} is not a valid Arsenic (.arsn) file"));
    }

    let recipient = resolve_recipient(recipient_spec)
        .ok_or_else(|| anyhow!("Cannot resolve recipient '{recipient_spec}': not a contact name or key file"))?;

    let pw = resolve_password(password, passwordfile.map(str::to_owned), "Password: ")?;

    arsenic_add_recipient_with_level(path, &pw, &recipient, kem_level.map(Into::into), &NoProgress)
        .map_err(|e| anyhow!(e))?;

    println!("Recipient added to {file}.");
    Ok(())
}

/// Remove a recipient keyslot, identified either by identity file or by slot index.
fn recipients_remove(
    file: &str,
    identity: Option<&str>,
    slot: Option<usize>,
    password: Option<String>,
    passwordfile: Option<&str>,
) -> Result<()> {
    let path = Path::new(file);
    if !path.is_file() {
        return Err(anyhow!("File not found: {file}"));
    }
    if !is_arsenic_file(path) {
        return Err(anyhow!("{file} is not a valid Arsenic (.arsn) file"));
    }

    // Resolve slot index.
    let slot_idx = match (identity, slot) {
        (Some(id_path), _) => {
            let entry = load_identity_file(Path::new(id_path))
                .ok_or_else(|| anyhow!("Cannot read identity file: {id_path}"))?;
            arsenic_find_slot_for_key(path, &entry)
                .ok_or_else(|| anyhow!("No keyslot in '{file}' matches '{id_path}'"))?
        }
        (None, Some(n)) => n,
        (None, None) => {
            return Err(anyhow!(
                "Specify a recipient with -i KEY_FILE or --slot N.\n\
                 Use `cryptyrust recipients list {file}` to see slot indices."
            ));
        }
    };

    let pw = resolve_password(password, passwordfile.map(str::to_owned), "Password: ")?;

    arsenic_remove_recipient(path, &pw, slot_idx, &NoProgress)
        .map_err(|e| anyhow!("{e}"))?;

    println!("Slot {slot_idx} removed from {file}.");
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

// ── Decrypt from an in-memory buffer (used for armored files) ─────────────────

fn decrypt_from_bytes(
    app: &Cli,
    ct: &[u8],
    out_str: &str,
    ui: &ProgressUpdater,
) -> Result<f64> {
    use std::io::Cursor;
    use arsenic::{decrypt_arsenic, decrypt_arsenic_with_key};

    let filesize = ct.len() as u64;
    let start = std::time::Instant::now();

    // Every attempt (re)creates the output; a failed one must not leave an
    // empty or partial file behind.
    let try_key = |key: &KeyEntry| -> Result<bool> {
        let mut cur = Cursor::new(ct);
        let mut out = std::fs::File::create(out_str)
            .with_context(|| format!("cannot create {out_str}"))?;
        let privkey = Secret::new(key.private_key);
        let ok = decrypt_arsenic_with_key(
            &mut cur, &mut out, &privkey, &key.mlkem_seed, ui, filesize,
        )
        .is_ok();
        if !ok {
            drop(out);
            let _ = std::fs::remove_file(out_str);
        }
        Ok(ok)
    };

    // Try asymmetric keys first.
    let explicit_identities: Vec<_> = app
        .identities()
        .iter()
        .filter_map(|p| load_identity_file(Path::new(p)))
        .collect();

    if !explicit_identities.is_empty() {
        for key in &explicit_identities {
            if try_key(key)? {
                eprintln!("Decrypted with identity: {}", key.name);
                return Ok(start.elapsed().as_secs_f64());
            }
        }
        return Err(anyhow!("none of the provided identity files can decrypt this armored file"));
    }

    for key in &load_keystore() {
        if try_key(key)? {
            eprintln!("Decrypted with stored key: {}", key.name);
            return Ok(start.elapsed().as_secs_f64());
        }
    }

    let password = get_password_for_decrypt(app)?;
    let mut cur = Cursor::new(ct);
    let mut out = std::fs::File::create(out_str)
        .with_context(|| format!("cannot create {out_str}"))?;
    if let Err(e) = decrypt_arsenic(&mut cur, &mut out, &password, ui, filesize) {
        drop(out);
        let _ = std::fs::remove_file(out_str);
        return Err(anyhow!(e));
    }
    Ok(start.elapsed().as_secs_f64())
}

// ── Passphrase slot management ────────────────────────────────────────────────

fn run_passphrase(cli: PassphraseCli) -> Result<()> {
    match cli.action {
        PassphraseAction::List { file } => {
            let count = arsenic_list_passphrases(Path::new(&file))
                .map_err(|e| anyhow!(e))?;
            match count {
                0 => println!("Password slots: 0  (this file opens with a keypair only)"),
                n => println!("Password slots: {n}"),
            }
        }

        PassphraseAction::Add { file, password, passwordfile, new_pass, new_pass_file } => {
            let existing_pw = resolve_password(password, passwordfile, "Existing password: ")?;
            let new_pw = resolve_password(
                new_pass, new_pass_file, "New passphrase (minimum 8 characters): ",
            )?;
            check_new_password(new_pw.expose()).map_err(|e| anyhow!(e))?;
            arsenic_add_passphrase(
                Path::new(&file), &existing_pw, &new_pw, &NoProgress,
            ).map_err(|e| anyhow!(e))?;
            println!("✓ Password added.");
        }

        PassphraseAction::Remove { file, password, passwordfile, remove_pass, remove_pass_file } => {
            let auth_pw = resolve_password(password, passwordfile, "Password: ")?;
            let rm_pw = resolve_password(remove_pass, remove_pass_file, "Password to remove: ")?;
            arsenic_remove_passphrase(
                Path::new(&file), &auth_pw, &rm_pw, &NoProgress,
            ).map_err(|e| anyhow!(e))?;
            println!("✓ Password removed.");
            println!("{OLD_COPIES_NOTE}");
        }
    }
    Ok(())
}

fn resolve_password(
    inline: Option<String>,
    file: Option<String>,
    prompt: &str,
) -> Result<Secret<String>> {
    if let Some(p) = inline { return Ok(Secret::new(p)); }
    if let Some(f) = file {
        return Ok(Secret::new(
            std::fs::read_to_string(&f)
                .with_context(|| format!("cannot read password file: {f}"))?
        ));
    }
    Ok(Secret::new(rpassword::prompt_password(prompt).context("could not read password")?))
}
