use arsenic::{
    bench_cipher_combinations, ArsenicParams, ArsenicStrength, CipherBenchResult, CipherId,
    KemLevel, Ui,
};
use eframe::egui;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use crate::file_utils::{
    cipher_from_key, cipher_to_key, check_new_password, is_armored_file, mode_from_flags,
    FileMeta, Mode,
};
use crate::job::{lock, FileStatus, JobState, PasswordPopup};
use arsenic::Secret;
use crate::keystore::{
    delete_key, load_contacts, load_keystore, save_contacts, save_key, ContactEntry, KeyEntry,
};
use crate::ui::UI;

pub enum BenchMsg {
    Progress(i32),
    Done(Vec<CipherBenchResult>),
}

// One flag per independent window/option of the UI: a state machine would
// not describe them better.
#[allow(clippy::struct_excessive_bools)]
pub struct CryptyApp {
    pub files: Vec<PathBuf>,
    /// Type and size of each queued file, read once when it is added.
    pub file_meta: HashMap<PathBuf, FileMeta>,
    pub mode: Mode,
    pub mixed: bool,
    pub job: JobState,
    pub popup: PasswordPopup,
    pub pw: String,
    pub pw_confirm: String,
    pub pw_show: bool,
    pub pw_error: Option<String>,
    pub pw_focus: bool,
    /// One bool per entry in `keys` — true when selected as an asymmetric recipient.
    pub pw_selected_own_keys: Vec<bool>,
    /// One bool per entry in `contacts` — true when selected as an asymmetric recipient.
    pub pw_selected_recipients: Vec<bool>,
    /// Index of the keypair selected for asymmetric decryption (decrypt mode only).
    pub decrypt_key_index: Option<usize>,
    pub arsenic_strength: ArsenicStrength,
    pub hdr_cipher: CipherId,
    pub pld_cipher: CipherId,
    /// ML-KEM security level for asymmetric keyslots (L768 default / L1024).
    pub kem_level: KemLevel,
    /// zstd compression level (None = disabled, 1–22 when enabled).
    pub compress: Option<i32>,
    /// Wrap encrypted output in ASCII armor.
    pub armor: bool,
    /// Sender info extracted after decryption — offered as "Add to contacts?".
    pub pending_contact_from_file: Option<arsenic::keystore::ContactEntry>,
    pub show_about: bool,
    pub dark_mode: bool,
    // Cipher benchmark state
    pub bench_running: bool,
    pub bench_progress: i32,
    pub bench_results: Option<Vec<CipherBenchResult>>,
    pub bench_rx: Option<mpsc::Receiver<BenchMsg>>,
    pub show_bench: bool,
    // Change-password popup state
    pub cpw_old: String,
    pub cpw_new: String,
    pub cpw_confirm: String,
    pub cpw_show: bool,
    pub cpw_error: Option<String>,
    pub cpw_focus: bool,
    // Key manager state
    pub keys: Vec<KeyEntry>,
    pub show_key_manager: bool,
    /// Name field for new key generation.
    pub km_new_name: String,
    /// Validation error for the new key form.
    pub km_error: Option<String>,
    /// Confirmation of the last successful key action (export).
    pub km_notice: Option<String>,
    /// Keystore locations shown in the key manager.
    pub keys_dir_label: String,
    pub contacts_path_label: String,
    /// Index of the key pending deletion confirmation (two-click safety).
    pub km_confirm_delete: Option<usize>,
    /// Index of the key whose secret key popup is open.
    pub km_show_privkey: Option<usize>,
    // Contact management state
    pub contacts: Vec<ContactEntry>,
    pub km_new_contact_name: String,
    /// X25519 public key (arsenic1...) for new contact.
    pub km_new_contact_key: String,
    /// ML-KEM-768 public key (arsenic1m...) for new contact.
    pub km_new_contact_mlkem_key: String,
    pub km_contact_error: Option<String>,
    pub km_confirm_delete_contact: Option<usize>,
}

impl CryptyApp {
    pub fn new(storage: Option<&dyn eframe::Storage>, system_dark: bool) -> Self {
        let dark_mode = storage
            .and_then(|s| s.get_string("dark_mode"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(system_dark);

        let arsenic_strength = storage
            .and_then(|s| s.get_string("arsenic_strength"))
            .and_then(|s| match s.as_str() {
                "interactive" => Some(ArsenicStrength::Interactive),
                "sensitive" => Some(ArsenicStrength::Sensitive),
                _ => None,
            })
            .unwrap_or(ArsenicStrength::Interactive);

        let hdr_cipher = storage
            .and_then(|s| s.get_string("hdr_cipher"))
            .and_then(|s| cipher_from_key(&s))
            .unwrap_or(CipherId::DeoxysII256);

        let pld_cipher = storage
            .and_then(|s| s.get_string("pld_cipher"))
            .and_then(|s| cipher_from_key(&s))
            .unwrap_or(CipherId::XChaCha20Poly1305);

        let kem_level = storage
            .and_then(|s| s.get_string("kem_level"))
            .and_then(|s| match s.as_str() {
                "1024" => Some(KemLevel::L1024),
                _ => None,
            })
            .unwrap_or(KemLevel::L768);

        let compress: Option<i32> = storage
            .and_then(|s| s.get_string("compress_level"))
            .and_then(|s| s.parse().ok())
            .filter(|level| (1..=22).contains(level));

        let armor = storage
            .and_then(|s| s.get_string("armor"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        Self {
            files: vec![],
            file_meta: HashMap::new(),
            mode: Mode::Encrypt,
            mixed: false,
            job: JobState::Idle,
            popup: PasswordPopup::Closed,
            pw: String::new(),
            pw_confirm: String::new(),
            pw_show: false,
            pw_error: None,
            pw_focus: false,
            pw_selected_own_keys: vec![],
            pw_selected_recipients: vec![],
            decrypt_key_index: None,
            arsenic_strength,
            hdr_cipher,
            pld_cipher,
            kem_level,
            compress,
            armor,
            pending_contact_from_file: None,
            show_about: false,
            dark_mode,
            bench_running: false,
            bench_progress: 0,
            bench_results: None,
            bench_rx: None,
            show_bench: false,
            cpw_old: String::new(),
            cpw_new: String::new(),
            cpw_confirm: String::new(),
            cpw_show: false,
            cpw_error: None,
            cpw_focus: false,
            keys: load_keystore(),
            show_key_manager: false,
            km_new_name: String::new(),
            km_error: None,
            km_notice: None,
            keys_dir_label: crate::keystore::keys_dir()
                .map_or_else(|| "unknown".into(), |p| p.to_string_lossy().into_owned()),
            contacts_path_label: crate::keystore::contacts_path()
                .map_or_else(|| "unknown".into(), |p| p.to_string_lossy().into_owned()),
            km_confirm_delete: None,
            km_show_privkey: None,
            contacts: load_contacts(),
            km_new_contact_name: String::new(),
            km_new_contact_key: String::new(),
            km_new_contact_mlkem_key: String::new(),
            km_contact_error: None,
            km_confirm_delete_contact: None,
        }
    }
}

/// Longest contact name kept from a file or an identity found in a header.
const MAX_CONTACT_NAME_CHARS: usize = 64;

/// Overwrite a password buffer before releasing it.
fn wipe(s: &mut String) {
    drop(Secret::new(std::mem::take(s)));
}

/// True if `name` would be misread by the contacts file parser.
fn is_reserved_contact_name(name: &str) -> bool {
    name.starts_with("mlkem:") || name.starts_with("sign-key:")
}

/// Make a contact name coming from outside (a `.pubkey` file, the sender field
/// of a decrypted file) safe to display and to store: single line, bounded
/// length, not a reserved prefix.
fn sanitize_contact_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut name: String = cleaned.trim().chars().take(MAX_CONTACT_NAME_CHARS).collect();
    if name.is_empty() {
        name = "contact".into();
    }
    if is_reserved_contact_name(&name) {
        name.insert(0, '_');
    }
    name
}

/// Recursively collect all regular files from `path`.
/// If `path` is a file, returns it directly.
/// Entries within a directory are sorted for deterministic ordering.
///
/// Symbolic links to directories found while walking are not followed: a link
/// pointing back to a parent would otherwise recurse forever.
fn collect_files_from_path(path: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if path.is_file() {
        result.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_dir(path, &mut result);
    }
    result
}

fn collect_dir(dir: &Path, result: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    children.sort();
    for child in children {
        // symlink_metadata describes the link itself, not its target.
        let Ok(meta) = std::fs::symlink_metadata(&child) else { continue };
        if meta.is_dir() {
            collect_dir(&child, result);
        } else if child.is_file() {
            result.push(child);
        }
    }
}

impl CryptyApp {
    /// Add files or directories. Directories are expanded recursively.
    /// Drag-and-drop of folders is handled automatically by this method.
    ///
    /// After a finished job the previous list is dropped first: those files
    /// have already been processed and must not be queued a second time.
    pub fn add_files(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        if matches!(self.job, JobState::Completed { .. }) {
            self.files.clear();
            self.file_meta.clear();
            self.pending_contact_from_file = None;
            self.job = JobState::Idle;
        }
        for p in paths {
            for file in collect_files_from_path(&p) {
                if !self.file_meta.contains_key(&file) {
                    self.file_meta.insert(file.clone(), FileMeta::read(&file));
                    self.files.push(file);
                }
            }
        }
        self.refresh_mode();
    }

    pub fn remove_file(&mut self, idx: usize) {
        let removed = self.files.remove(idx);
        self.file_meta.remove(&removed);
        self.refresh_mode();
    }

    fn refresh_mode(&mut self) {
        let flags = self.files.iter().map(|f| self.is_encrypted(f));
        match mode_from_flags(flags) {
            Some(m) => {
                self.mode = m;
                self.mixed = false;
            }
            None => {
                self.mixed = true;
            }
        }
    }

    /// Cached "is an Arsenic file" flag of a queued file.
    pub fn is_encrypted(&self, path: &Path) -> bool {
        self.file_meta.get(path).is_some_and(|m| m.encrypted)
    }

    pub fn clear_all(&mut self) {
        self.files.clear();
        self.file_meta.clear();
        self.mode = Mode::Encrypt;
        self.mixed = false;
        wipe(&mut self.pw);
        wipe(&mut self.pw_confirm);
        self.pw_error = None;
        self.popup = PasswordPopup::Closed;
        self.job = JobState::Idle;
    }

    /// Dismiss the password popup, keeping the file list intact.
    pub fn close_popup(&mut self) {
        wipe(&mut self.pw);
        wipe(&mut self.pw_confirm);
        self.pw_error = None;
        self.popup = PasswordPopup::Closed;
    }

    pub fn open_popup(&mut self) {
        wipe(&mut self.pw);
        wipe(&mut self.pw_confirm);
        self.pw_error = None;
        self.pw_show = false;
        self.pw_focus = true;
        self.pw_selected_own_keys = vec![false; self.keys.len()];
        self.pw_selected_recipients = vec![false; self.contacts.len()];
        self.decrypt_key_index = None;
        self.popup = PasswordPopup::Open;
    }

    /// For decrypt mode: if every file has a keyslot for one of the stored
    /// keypairs, start decryption immediately without showing any popup.
    /// Otherwise show the password popup — the job still uses a matching
    /// keypair for the files that have one, and the password for the others.
    pub fn open_popup_or_auto_decrypt(&mut self, ctx: &egui::Context) {
        if self.mode == Mode::Decrypt
            && !self.keys.is_empty()
            && !self.files.is_empty()
            && self.files.iter().all(|f| self.find_matching_key_any_format(f).is_some())
        {
            self.popup = PasswordPopup::Closed;
            self.start_job(ctx.clone(), String::new());
            return;
        }
        self.open_popup();
    }

    /// Probe a file for a matching keypair, handling both binary and armored formats.
    fn find_matching_key_any_format(&self, path: &std::path::Path) -> Option<usize> {
        use std::io::Cursor;
        use arsenic::{HybridPrivKey, find_decrypting_key};

        let hybrid_keys: Vec<HybridPrivKey<'_>> = self.keys.iter()
            .map(|k| HybridPrivKey { x25519_sk: &k.private_key, mlkem_seed: &k.mlkem_seed })
            .collect();

        // Only an armored file is loaded in memory; a binary one is probed
        // through its header, whatever its size.
        if is_armored_file(path) {
            let text = std::fs::read_to_string(path).ok()?;
            let ct = arsenic::dearmor(&text).ok()?;
            return find_decrypting_key(&mut Cursor::new(ct), &hybrid_keys).ok().flatten();
        }
        let mut f = std::fs::File::open(path).ok()?;
        find_decrypting_key(&mut f, &hybrid_keys).ok().flatten()
    }

    pub fn open_change_pw_popup(&mut self) {
        self.cpw_old.clear();
        self.cpw_new.clear();
        self.cpw_confirm.clear();
        self.cpw_error = None;
        self.cpw_show = false;
        self.cpw_focus = true;
        self.popup = PasswordPopup::ChangePw;
    }

    pub fn validate_and_start(&mut self, ctx: &egui::Context) {
        let n_sel = self.pw_selected_own_keys.iter().filter(|&&s| s).count()
            + self.pw_selected_recipients.iter().filter(|&&s| s).count();

        let password = if self.pw.is_empty() {
            match self.mode {
                Mode::Decrypt => {
                    if self.decrypt_key_index.is_none() {
                        self.pw_error =
                            Some("Enter a password or select a keypair.".into());
                        return;
                    }
                    // Asymmetric path: password unused.
                    String::new()
                }
                Mode::Encrypt if n_sel == 0 => {
                    self.pw_error =
                        Some("Enter a password or select at least one recipient.".into());
                    return;
                }
                Mode::Encrypt => {
                    // No password but recipients selected: the file gets no
                    // password slot, only the selected keypairs can open it.
                    String::new()
                }
            }
        } else {
            if self.mode == Mode::Encrypt {
                if let Err(e) = check_new_password(&self.pw) {
                    self.pw_error = Some(e);
                    return;
                }
                if self.pw != self.pw_confirm {
                    self.pw_error = Some("Passwords do not match.".into());
                    return;
                }
            }
            self.pw.clone()
        };

        self.popup = PasswordPopup::Closed;
        wipe(&mut self.pw);
        wipe(&mut self.pw_confirm);
        self.start_job(ctx.clone(), password);
    }

    pub fn validate_and_change_pw(&mut self, ctx: &egui::Context) {
        if self.cpw_old.is_empty() {
            self.cpw_error = Some("Current password cannot be empty.".into());
            return;
        }
        if let Err(e) = check_new_password(&self.cpw_new) {
            self.cpw_error = Some(format!("New password: {e}"));
            return;
        }
        if self.cpw_new != self.cpw_confirm {
            self.cpw_error = Some("New passwords do not match.".into());
            return;
        }
        let old_pw = std::mem::take(&mut self.cpw_old);
        let new_pw = std::mem::take(&mut self.cpw_new);
        wipe(&mut self.cpw_confirm);
        let file = self.files[0].clone();
        self.popup = PasswordPopup::Closed;
        self.job.start_change_pw(file, old_pw, new_pw, ctx.clone());
    }

    pub fn start_bench(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel::<BenchMsg>();
        self.bench_rx = Some(rx);
        self.bench_running = true;
        self.bench_progress = 0;
        self.bench_results = None;
        self.show_bench = true;

        thread::spawn({
            let tx = tx;
            let ctx = ctx;
            move || {
                struct BenchUi {
                    tx: mpsc::Sender<BenchMsg>,
                    ctx: egui::Context,
                }
                impl Ui for BenchUi {
                    fn output(&self, pct: i32) {
                        let _ = self.tx.send(BenchMsg::Progress(pct));
                        self.ctx.request_repaint();
                    }
                }
                let results = bench_cipher_combinations(
                    32,
                    &BenchUi {
                        tx: tx.clone(),
                        ctx: ctx.clone(),
                    },
                );
                let _ = tx.send(BenchMsg::Done(results));
                ctx.request_repaint();
            }
        });
    }

    /// Generate a new keypair with the current `km_new_name` and persist it.
    pub fn km_generate_key(&mut self) {
        let name = self.km_new_name.trim().to_string();
        if name.is_empty() {
            self.km_error = Some("Name cannot be empty.".into());
            return;
        }
        if self.keys.iter().any(|k| k.name == name) {
            self.km_error = Some(format!("A key named \"{name}\" already exists."));
            return;
        }
        let mut entry = KeyEntry::generate(name);
        if let Err(e) = save_key(&mut entry) {
            self.km_error = Some(format!("Could not save key: {e}"));
            return;
        }
        self.keys.push(entry);
        self.km_new_name.clear();
        self.km_error = None;
    }

    /// Add a contact from the form fields and persist.
    pub fn km_add_contact(&mut self) {
        use arsenic::decode_pubkey;
        let name = self.km_new_contact_name.trim().to_string();
        if name.is_empty() {
            self.km_contact_error = Some("Name cannot be empty.".into());
            return;
        }
        if name.chars().any(char::is_control) {
            self.km_contact_error = Some("Name must not contain control characters.".into());
            return;
        }
        if name.chars().count() > MAX_CONTACT_NAME_CHARS {
            self.km_contact_error =
                Some(format!("Name is too long (max {MAX_CONTACT_NAME_CHARS} characters)."));
            return;
        }
        if is_reserved_contact_name(&name) {
            self.km_contact_error =
                Some("Name must not start with \"mlkem:\" or \"sign-key:\".".into());
            return;
        }
        if self.contacts.iter().any(|c| c.name == name) {
            self.km_contact_error = Some(format!("A contact named \"{name}\" already exists."));
            return;
        }
        let key_str = self.km_new_contact_key.trim().to_string();
        let Some(public_key) = decode_pubkey(&key_str) else {
            self.km_contact_error =
                Some("Invalid X25519 key — expected arsenic1… format.".into());
            return;
        };
        let mlkem_str = self.km_new_contact_mlkem_key.trim().to_string();
        let Some(mlkem_key) = arsenic::decode_mlkem_pubkey(&mlkem_str) else {
            self.km_contact_error =
                Some("Invalid ML-KEM key — expected arsenic1m… format.".into());
            return;
        };
        self.contacts.push(ContactEntry {
            name,
            public_key,
            mlkem_public_key: Box::new(mlkem_key),
        });
        if !self.persist_new_contact() {
            return;
        }
        self.km_new_contact_name.clear();
        self.km_new_contact_key.clear();
        self.km_new_contact_mlkem_key.clear();
    }

    /// Save the contact list after pushing a new entry. On failure the entry
    /// is dropped again so the list on screen matches the one on disk.
    fn persist_new_contact(&mut self) -> bool {
        match save_contacts(&self.contacts) {
            Ok(()) => {
                self.km_contact_error = None;
                true
            }
            Err(e) => {
                self.contacts.pop();
                self.km_contact_error = Some(format!("Could not save contacts: {e}"));
                false
            }
        }
    }

    /// Delete the contact at `index` and persist.
    pub fn km_delete_contact(&mut self, index: usize) {
        if index < self.contacts.len() {
            let removed = self.contacts.remove(index);
            if let Err(e) = save_contacts(&self.contacts) {
                self.contacts.insert(index, removed);
                self.km_contact_error = Some(format!("Could not save contacts: {e}"));
            }
        }
        self.km_confirm_delete_contact = None;
    }

    /// Delete the key at `index` and remove its `.key` file.
    pub fn km_delete_key(&mut self, index: usize) {
        if index < self.keys.len() {
            match delete_key(&self.keys[index]) {
                Ok(()) => {
                    self.keys.remove(index);
                    self.km_error = None;
                }
                Err(e) => self.km_error = Some(format!("Could not delete key file: {e}")),
            }
        }
        self.km_notice = None;
        self.km_confirm_delete = None;
    }

    /// Read sender identity from the file and propose adding as contact if unknown.
    pub fn extract_sender_from_file(&mut self, path: &std::path::Path) {
        use arsenic::arsenic_read_sender_info;
        let Some(sender) = arsenic_read_sender_info(path) else { return };
        // A malformed key could never be encrypted to: do not offer it.
        if !arsenic::mlkem_pubkey_is_valid(&sender.mlkem_pk) { return; }
        // The sender field is a claim written by whoever made the file: clean
        // the name and keep it distinct from existing contacts.
        let (x25519_pk, mlkem_pk) = (sender.x25519_pk, sender.mlkem_pk);
        let name = self.unique_contact_name(&sanitize_contact_name(&sender.name));
        if self.contacts.iter().any(|c| c.public_key == x25519_pk) { return; }
        if self.keys.iter().any(|k| k.public_key == x25519_pk) { return; }
        self.pending_contact_from_file = Some(arsenic::keystore::ContactEntry {
            name,
            public_key: x25519_pk,
            mlkem_public_key: Box::new(mlkem_pk),
        });
    }

    /// `name`, or `name (2)`, `name (3)`… if a contact already uses it.
    fn unique_contact_name(&self, name: &str) -> String {
        let taken = |n: &str| self.contacts.iter().any(|c| c.name == n);
        if !taken(name) {
            return name.to_string();
        }
        (2..u32::MAX)
            .map(|i| format!("{name} ({i})"))
            .find(|n| !taken(n))
            .unwrap_or_else(|| name.to_string())
    }

    /// Confirm adding the pending contact extracted from the last decrypted file.
    pub fn confirm_add_contact_from_file(&mut self) {
        if let Some(entry) = self.pending_contact_from_file.take() {
            self.contacts.push(entry);
            self.persist_new_contact();
        }
    }

    /// Export the public parts of keypair `index` as a `.pubkey` file.
    /// Automatically includes the active signing verifying key so the recipient
    /// gets both the encryption key and the signing key in one file.
    pub fn km_export_key(&mut self, index: usize) {
        let Some(entry) = self.keys.get(index) else { return };
        let content = arsenic::keystore::serialize_pubkey(entry);
        let filename = format!("{}.pubkey", entry.name);
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Public key", &["pubkey"])
            .set_file_name(&filename)
            .save_file()
        {
            match std::fs::write(&path, &content) {
                Ok(()) => {
                    self.km_error = None;
                    self.km_notice = Some(format!("✓ Exported to {}", path.display()));
                }
                Err(e) => {
                    self.km_notice = None;
                    self.km_error = Some(format!("Export failed: {e}"));
                }
            }
        }
    }

    /// Open a file picker and import a contact from a `.pubkey` or `.key` file.
    pub fn km_import_contact_from_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Public key files", &["pubkey", "key"])
            .set_title("Import contact — select a .pubkey or .key file")
            .pick_file()
        {
            self.km_do_import_contact(path);
        }
    }

    /// Core import logic — also used by drag-and-drop.
    pub fn km_do_import_contact(&mut self, path: PathBuf) {
        let content = match std::fs::read_to_string(&path) {
            Ok(c)  => c,
            Err(e) => { self.km_contact_error = Some(format!("Cannot read file: {e}")); return; }
        };
        let Some(mut entry) = arsenic::keystore::parse_pubkey_file(&content, path) else {
            self.km_contact_error = Some("No valid public key found in this file.".into());
            return;
        };
        entry.name = sanitize_contact_name(&entry.name);
        if self.keys.iter().any(|k| k.public_key == entry.public_key) {
            self.km_contact_error = Some(format!("\"{}\" is one of your own keypairs.", entry.name));
            return;
        }
        if self.contacts.iter().any(|c| c.public_key == entry.public_key) {
            self.km_contact_error = Some("A contact with this public key already exists.".into());
            return;
        }
        if self.contacts.iter().any(|c| c.name == entry.name) {
            self.km_contact_error = Some(format!("A contact named \"{}\" already exists.", entry.name));
            return;
        }
        self.contacts.push(entry);
        self.persist_new_contact();
    }

    /// True if a dropped file should be imported as a contact rather than
    /// queued: a `.pubkey`/`.key` file that really holds an Arsenic public key.
    /// Any other `.key` file (a TLS key, for instance) stays encryptable.
    fn is_contact_file(path: &Path) -> bool {
        const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext != "pubkey" && ext != "key" {
            return false;
        }
        if std::fs::metadata(path).map_or(true, |m| m.len() > MAX_KEY_FILE_BYTES) {
            return false;
        }
        std::fs::read_to_string(path)
            .ok()
            .and_then(|c| arsenic::keystore::parse_pubkey_file(&c, path.to_path_buf()))
            .is_some()
    }

    fn start_job(&mut self, ctx: egui::Context, password: String) {
        let recipients: Vec<arsenic::HybridRecipient> = self
            .keys
            .iter()
            .zip(self.pw_selected_own_keys.iter())
            .filter(|(_, &sel)| sel)
            .map(|(k, _)| k.as_recipient())
            .chain(
                self.contacts
                    .iter()
                    .zip(self.pw_selected_recipients.iter())
                    .filter(|(_, &sel)| sel)
                    .map(|(c, _)| c.as_recipient()),
            )
            .collect();

        // Decrypt mode: every stored keypair is a candidate; the job picks the
        // one matching each file and falls back to the password otherwise.
        let keys = match self.mode {
            Mode::Decrypt => self.keys.clone(),
            Mode::Encrypt => Vec::new(),
        };

        let params = ArsenicParams {
            hdr_cipher: self.hdr_cipher,
            pld_cipher: self.pld_cipher,
            recipients,
            kem_level: self.kem_level,
            compress: self.compress,
            sender_name: None,
            sender_x25519_pk: None,
            sender_mlkem_pk: None,
            ..ArsenicParams::from(self.arsenic_strength)
        };
        self.job
            .start(self.files.clone(), self.mode, params, self.armor, password, keys, ctx);
    }
}

impl eframe::App for CryptyApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string("dark_mode", self.dark_mode.to_string());
        storage.set_string(
            "arsenic_strength",
            match self.arsenic_strength {
                ArsenicStrength::Interactive => "interactive",
                ArsenicStrength::Sensitive => "sensitive",
            }
            .to_string(),
        );
        storage.set_string("hdr_cipher", cipher_to_key(self.hdr_cipher).to_string());
        storage.set_string("pld_cipher", cipher_to_key(self.pld_cipher).to_string());
        storage.set_string("kem_level", match self.kem_level {
            KemLevel::L768  => "768",
            KemLevel::L1024 => "1024",
        }.to_string());
        if let Some(level) = self.compress {
            storage.set_string("compress_level", level.to_string());
        } else {
            storage.set_string("compress_level", "none".to_string());
        }
        storage.set_string("armor", self.armor.to_string());
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(if self.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });

        // Handle drag & drop
        if self.popup == PasswordPopup::Closed
            && matches!(self.job, JobState::Idle | JobState::Completed { .. })
        {
            let dropped: Vec<PathBuf> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            if !dropped.is_empty() {
                // Route dropped files: .pubkey/.key → import as contact,
                // everything else → encrypt/decrypt queue.
                let mut to_encrypt: Vec<PathBuf> = Vec::new();
                for path in dropped {
                    if Self::is_contact_file(&path) {
                        self.km_do_import_contact(path);
                        // Open key manager so the user sees the result.
                        if !self.show_key_manager { self.show_key_manager = true; }
                    } else {
                        to_encrypt.push(path);
                    }
                }
                if !to_encrypt.is_empty() {
                    self.add_files(to_encrypt);
                }
            }
        }

        // Update job progress
        let mut job_completed = None;
        if let JobState::Running {
            progress,
            receiver,
            current_file,
            processing_files,
            file_statuses,
            success_label,
            ..
        } = &self.job
        {
            while let Ok((file_index, pct)) = receiver.try_recv() {
                lock(progress).insert(file_index, pct);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));

            let current = *lock(current_file);
            if current == usize::MAX {
                let statuses = lock(file_statuses).clone();
                job_completed =
                    Some((processing_files.clone(), statuses, success_label.clone()));
            }
        }

        if let Some((files, statuses, success_label)) = job_completed {
            // Only offer the sender of a file that was actually decrypted.
            let first_ok = matches!(statuses.first(), Some(FileStatus::Success));
            if self.mode == Mode::Decrypt && first_ok {
                if let Some(path) = files.first() {
                    self.extract_sender_from_file(path);
                }
            } else {
                self.pending_contact_from_file = None;
            }
            self.job = JobState::Completed {
                files,
                statuses,
                success_label,
            };
        }

        // Poll benchmark background thread
        if self.bench_running {
            let msgs: Vec<BenchMsg> = self
                .bench_rx
                .as_ref()
                .map(|rx| rx.try_iter().collect())
                .unwrap_or_default();
            for msg in msgs {
                match msg {
                    BenchMsg::Progress(p) => self.bench_progress = p,
                    BenchMsg::Done(results) => {
                        self.bench_results = Some(results);
                        self.bench_running = false;
                        self.bench_rx = None;
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        UI::render(self, ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_names_from_outside_are_made_safe() {
        assert_eq!(sanitize_contact_name("  Alice  "), "Alice");
        // A newline would start a new entry in the contacts file.
        assert_eq!(sanitize_contact_name("Eve\narsenic1xyz"), "Eve arsenic1xyz");
        assert_eq!(sanitize_contact_name("\t\n"), "contact");
        // Reserved prefixes would be read as key lines.
        assert_eq!(sanitize_contact_name("mlkem:abc"), "_mlkem:abc");
        assert_eq!(sanitize_contact_name("sign-key:abc"), "_sign-key:abc");
        assert_eq!(
            sanitize_contact_name(&"x".repeat(500)).chars().count(),
            MAX_CONTACT_NAME_CHARS
        );
    }

    #[test]
    fn collect_files_walks_folders_in_order() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub/deep")).unwrap();
        for f in ["b.txt", "a.txt", "sub/c.txt", "sub/deep/d.txt"] {
            std::fs::write(dir.path().join(f), b"x").unwrap();
        }
        let found: Vec<PathBuf> = collect_files_from_path(dir.path())
            .into_iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().to_path_buf())
            .collect();
        let expected: Vec<PathBuf> =
            ["a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"].iter().map(PathBuf::from).collect();
        assert_eq!(found, expected);
        assert_eq!(
            collect_files_from_path(&dir.path().join("a.txt")),
            [dir.path().join("a.txt")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_files_survives_symlink_loops() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/real.txt"), b"x").unwrap();
        // A link back to the parent, and a link to a regular file.
        symlink(dir.path(), dir.path().join("sub/loop")).unwrap();
        symlink(dir.path().join("sub/real.txt"), dir.path().join("link.txt")).unwrap();

        let found = collect_files_from_path(dir.path());
        assert_eq!(found, [dir.path().join("link.txt"), dir.path().join("sub/real.txt")]);
    }
}
