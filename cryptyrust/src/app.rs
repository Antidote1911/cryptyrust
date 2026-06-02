use arsenic::{
    bench_cipher_combinations, ArsenicParams, ArsenicStrength, CipherBenchResult, CipherId,
    KemLevel, SignatureStatus, Ui,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use crate::file_utils::{cipher_from_key, cipher_to_key, detect_mode, Mode};
use crate::job::{JobState, PasswordPopup};
use crate::keystore::{
    delete_key, load_contacts, load_keystore, save_contacts, save_key, ContactEntry, KeyEntry,
    save_signing_key, SigningKeyEntry,
};
use crate::ui::UI;

pub enum BenchMsg {
    Progress(i32),
    Done(Vec<CipherBenchResult>),
}

pub struct CryptyApp {
    pub files: Vec<PathBuf>,
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
    /// Index into `signing_keys` of the active signing key (None = no signature).
    pub signing_key_index: Option<usize>,
    /// Loaded ML-DSA-65 signing keys from the signing-keys keystore.
    pub signing_keys: Vec<arsenic::keystore::SigningKeyEntry>,
    /// Signature status of the last decrypted file.
    pub last_sig_status: Option<SignatureStatus>,
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
                _      => Some(KemLevel::L768),
            })
            .unwrap_or(KemLevel::L768);

        Self {
            files: vec![],
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
            signing_key_index: None,
            signing_keys: arsenic::keystore::load_signing_keystore(),
            last_sig_status: None,
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

/// Recursively collect all regular files from `path`.
/// If `path` is a file, returns it directly.
/// Entries within a directory are sorted for deterministic ordering.
fn collect_files_from_path(path: &PathBuf) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.clone()];
    }
    if path.is_dir() {
        let mut result = Vec::new();
        if let Ok(entries) = std::fs::read_dir(path) {
            let mut children: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .collect();
            children.sort();
            for child in children {
                result.extend(collect_files_from_path(&child));
            }
        }
        return result;
    }
    vec![]
}

impl CryptyApp {
    /// Add files or directories. Directories are expanded recursively.
    /// Drag-and-drop of folders is handled automatically by this method.
    pub fn add_files(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        for p in paths {
            for file in collect_files_from_path(&p) {
                if !self.files.contains(&file) {
                    self.files.push(file);
                }
            }
        }
        self.refresh_mode();
    }

    pub fn remove_file(&mut self, idx: usize) {
        self.files.remove(idx);
        self.refresh_mode();
    }

    fn refresh_mode(&mut self) {
        match detect_mode(&self.files) {
            Some(m) => {
                self.mode = m;
                self.mixed = false;
            }
            None => {
                self.mixed = true;
            }
        }
    }

    pub fn clear_all(&mut self) {
        self.files.clear();
        self.mode = Mode::Encrypt;
        self.mixed = false;
        self.pw.clear();
        self.pw_confirm.clear();
        self.pw_error = None;
        self.popup = PasswordPopup::Closed;
        self.job = JobState::Idle;
    }

    pub fn open_popup(&mut self) {
        self.pw.clear();
        self.pw_confirm.clear();
        self.pw_error = None;
        self.pw_show = false;
        self.pw_focus = true;
        self.pw_selected_own_keys = vec![false; self.keys.len()];
        self.pw_selected_recipients = vec![false; self.contacts.len()];
        self.decrypt_key_index = None;
        self.popup = PasswordPopup::Open;
    }

    /// For decrypt mode: probe the first file's header to find a matching keypair.
    /// If one is found, start decryption immediately without showing any popup.
    /// Otherwise fall back to the standard password popup.
    pub fn open_popup_or_auto_decrypt(&mut self, ctx: &egui::Context) {
        if self.mode == Mode::Decrypt && !self.keys.is_empty() {
            if let Some(path) = self.files.first().cloned() {
                if let Some(idx) = arsenic::arsenic_find_matching_key(&path, &self.keys) {
                    self.decrypt_key_index = Some(idx);
                    self.popup = PasswordPopup::Closed;
                    self.start_job(ctx.clone(), String::new());
                    return;
                }
            }
        }
        self.open_popup();
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
        // Signing is mandatory for encryption.
        if self.mode == Mode::Encrypt && self.signing_key_index.is_none() {
            self.pw_error = Some(if self.signing_keys.is_empty() {
                "Signing is required — generate a signing key in Key Manager first.".into()
            } else {
                "Signing is required — select a signing key in the Config menu.".into()
            });
            return;
        }

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
                    // No password but recipients selected: generate a random KEK.
                    // The symmetric keyslot will be inaccessible; only the
                    // asymmetric keyslots can decrypt.
                    let r = arsenic::random_bytes_32();
                    r.iter().map(|b| format!("{b:02x}")).collect::<String>()
                }
            }
        } else {
            if self.mode == Mode::Encrypt && self.pw != self.pw_confirm {
                self.pw_error = Some("Passwords do not match.".into());
                return;
            }
            self.pw.clone()
        };

        self.popup = PasswordPopup::Closed;
        self.pw.clear();
        self.pw_confirm.clear();
        self.start_job(ctx.clone(), password);
    }

    pub fn validate_and_change_pw(&mut self, ctx: &egui::Context) {
        if self.cpw_old.is_empty() {
            self.cpw_error = Some("Current password cannot be empty.".into());
            return;
        }
        if self.cpw_new.is_empty() {
            self.cpw_error = Some("New password cannot be empty.".into());
            return;
        }
        if self.cpw_new != self.cpw_confirm {
            self.cpw_error = Some("New passwords do not match.".into());
            return;
        }
        let old_pw = std::mem::take(&mut self.cpw_old);
        let new_pw = std::mem::take(&mut self.cpw_new);
        self.cpw_confirm.clear();
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
            let tx = tx.clone();
            let ctx = ctx.clone();
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
        if name.contains('\t') || name.contains('\n') {
            self.km_contact_error = Some("Name must not contain tab or newline.".into());
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
            signing_verifying_key: None,
        });
        save_contacts(&self.contacts);
        self.km_new_contact_name.clear();
        self.km_new_contact_key.clear();
        self.km_new_contact_mlkem_key.clear();
        self.km_contact_error = None;
    }

    /// Delete the contact at `index` and persist.
    pub fn km_delete_contact(&mut self, index: usize) {
        if index < self.contacts.len() {
            self.contacts.remove(index);
            save_contacts(&self.contacts);
        }
        self.km_confirm_delete_contact = None;
    }

    /// Delete the key at `index` and remove its `.key` file.
    pub fn km_delete_key(&mut self, index: usize) {
        if index < self.keys.len() {
            delete_key(&self.keys[index]);
            self.keys.remove(index);
        }
        self.km_confirm_delete = None;
    }

    /// Generate a new ML-DSA-65 signing key and save it to the signing-keys keystore.
    pub fn km_generate_signing_key(&mut self) {
        let name = self.km_new_name.trim().to_string();
        if name.is_empty() {
            self.km_error = Some("Name cannot be empty.".into());
            return;
        }
        if self.signing_keys.iter().any(|k| k.name == name) {
            self.km_error = Some(format!("A signing key named \"{name}\" already exists."));
            return;
        }
        let mut entry = SigningKeyEntry::generate(name);
        if let Err(e) = save_signing_key(&mut entry) {
            self.km_error = Some(format!("Could not save signing key: {e}"));
            return;
        }
        self.signing_keys.push(entry);
        self.km_new_name.clear();
        self.km_error = None;
    }

    /// Delete the signing key at `index` and remove its `.sigkey` file.
    pub fn km_delete_signing_key(&mut self, index: usize) {
        if index < self.signing_keys.len() {
            let entry = &self.signing_keys[index];
            if let Some(ref path) = entry.file_path {
                let _ = std::fs::remove_file(path);
            }
            // Adjust active signing key index.
            if self.signing_key_index == Some(index) {
                self.signing_key_index = None;
            } else if let Some(i) = self.signing_key_index {
                if i > index { self.signing_key_index = Some(i - 1); }
            }
            self.signing_keys.remove(index);
        }
    }

    /// Export the ML-DSA-65 verifying key of signing key `index` as a `.sigpub` file.
    pub fn km_export_sign_pubkey(&mut self, index: usize) {
        let Some(entry) = self.signing_keys.get(index) else { return };
        let content  = arsenic::keystore::serialize_sign_pubkey(entry);
        let filename = format!("{}.sigpub", entry.name);
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Signing public key", &["sigpub"])
            .set_file_name(&filename)
            .save_file()
        {
            match std::fs::write(&path, &content) {
                Ok(()) => self.km_error = Some(format!("✓ Exported to {}", path.display())),
                Err(e) => self.km_error = Some(format!("Export failed: {e}")),
            }
        }
    }

    /// Open a `.sigpub` file and attach its verifying key to the contact at `contact_index`.
    pub fn km_import_sign_pubkey_for_contact(&mut self, contact_index: usize) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Signing public key", &["sigpub"])
            .set_title("Import signing public key for contact")
            .pick_file()
        else { return };

        let content = match std::fs::read_to_string(&path) {
            Ok(c)  => c,
            Err(e) => { self.km_contact_error = Some(format!("Cannot read file: {e}")); return; }
        };
        let (_, vk) = match arsenic::keystore::parse_sign_pubkey_file(&content, path) {
            Some(r) => r,
            None    => { self.km_contact_error = Some("No valid signing key found in file.".into()); return; }
        };
        if let Some(c) = self.contacts.get_mut(contact_index) {
            c.signing_verifying_key = Some(Box::new(vk));
            save_contacts(&self.contacts);
            self.km_contact_error = None;
        }
    }

    /// Check the signature on a file against own signing keys then the contact trust store.
    pub fn check_and_store_sig_status(&mut self, path: &std::path::Path) {
        // Read the embedded verifying key first.
        let vk = match arsenic::arsenic_read_verifying_key(path) {
            Some(v) => v,
            None    => { self.last_sig_status = Some(arsenic::SignatureStatus::NotSigned); return; }
        };
        // 1. Check own signing keys (self-signed files).
        for sk in &self.signing_keys {
            if sk.verifying_key.as_slice() == vk.as_slice() {
                self.last_sig_status = Some(arsenic::SignatureStatus::SignedByKnown(
                    format!("{} (you)", sk.name),
                ));
                return;
            }
        }
        // 2. Check trusted contacts.
        self.last_sig_status = Some(arsenic::arsenic_check_signature(path, &self.contacts));
    }

    /// Import a .sigpub file and attach the verifying key to a contact by name,
    /// or add a new contact with only a signing key (for future key exchange).
    pub fn km_import_sigpub_global(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Signing public key", &["sigpub"])
            .set_title("Import signing public key (.sigpub)")
            .pick_file()
        else { return };

        let content = match std::fs::read_to_string(&path) {
            Ok(c)  => c,
            Err(e) => { self.km_contact_error = Some(format!("Cannot read file: {e}")); return; }
        };
        let (name, vk) = match arsenic::keystore::parse_sign_pubkey_file(&content, path) {
            Some(r) => r,
            None    => { self.km_contact_error = Some("No valid signing key found in this file.".into()); return; }
        };
        // Attach to existing contact with same name (case-insensitive).
        if let Some(c) = self.contacts.iter_mut().find(|c| c.name.eq_ignore_ascii_case(&name)) {
            c.signing_verifying_key = Some(Box::new(vk));
            save_contacts(&self.contacts);
            self.km_contact_error = Some(format!("✓ Signing key added to contact \"{name}\""));
        } else {
            self.km_contact_error = Some(format!(
                "No contact named \"{name}\" found. Add them as a contact first, then import their .sigpub."
            ));
        }
    }

    /// Export the public parts of keypair `index` as a `.pubkey` file.
    /// Automatically includes the active signing verifying key so the recipient
    /// gets both the encryption key and the signing key in one file.
    pub fn km_export_key(&mut self, index: usize) {
        let Some(entry) = self.keys.get(index) else { return };
        let signing_vk: Option<[u8; 1952]> = self.signing_key_index
            .and_then(|i| self.signing_keys.get(i))
            .map(|sk| *sk.verifying_key);
        let content  = arsenic::keystore::serialize_pubkey(
            entry,
            signing_vk.as_ref(),
        );
        let filename = format!("{}.pubkey", entry.name);
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Public key", &["pubkey"])
            .set_file_name(&filename)
            .save_file()
        {
            match std::fs::write(&path, &content) {
                Ok(()) => self.km_error = Some(format!("✓ Exported to {}", path.display())),
                Err(e) => self.km_error = Some(format!("Export failed: {e}")),
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
        let entry = match arsenic::keystore::parse_pubkey_file(&content, path) {
            Some(e) => e,
            None    => { self.km_contact_error = Some("No valid public key found in this file.".into()); return; }
        };
        if self.contacts.iter().any(|c| c.name == entry.name) {
            self.km_contact_error = Some(format!("A contact named \"{}\" already exists.", entry.name));
            return;
        }
        self.contacts.push(entry);
        save_contacts(&self.contacts);
        self.km_contact_error = None;
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

        // For decrypt mode: retrieve the selected keypair (if any).
        let privkey = self
            .decrypt_key_index
            .and_then(|i| self.keys.get(i))
            .cloned();

        // Optional ML-DSA-65 signing key seed.
        let signing_key = self.signing_key_index
            .and_then(|i| self.signing_keys.get(i))
            .map(|sk| sk.seed);

        let params = ArsenicParams {
            hdr_cipher: self.hdr_cipher,
            pld_cipher: self.pld_cipher,
            recipients,
            kem_level: self.kem_level,
            signing_key,
            ..ArsenicParams::from(self.arsenic_strength)
        };
        self.job
            .start(self.files.clone(), self.mode, params, password, privkey, ctx);
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
                    let ext = path.extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if ext == "pubkey" || ext == "key" {
                        self.km_do_import_contact(path);
                        // Open key manager so the user sees the result.
                        if !self.show_key_manager { self.show_key_manager = true; }
                    } else {
                        to_encrypt.push(path);
                    }
                }
                if !to_encrypt.is_empty() {
                    self.job = JobState::Idle;
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
                progress.lock().unwrap().insert(file_index, pct);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));

            let current = *current_file.lock().unwrap();
            if current == usize::MAX {
                let statuses = file_statuses.lock().unwrap().clone();
                job_completed =
                    Some((processing_files.clone(), statuses, success_label.clone()));
            }
        }

        if let Some((files, statuses, success_label)) = job_completed {
            // After decrypt, check the signature on the first file against the trust store.
            if self.mode == Mode::Decrypt {
                if let Some(path) = files.first() {
                    self.check_and_store_sig_status(path);
                }
            } else {
                self.last_sig_status = None;
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
