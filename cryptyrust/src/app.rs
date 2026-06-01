use arsenic::{
    bench_cipher_combinations, ArsenicParams, ArsenicStrength, CipherBenchResult, CipherId, Ui,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use crate::file_utils::{cipher_from_key, cipher_to_key, detect_mode, Mode};
use crate::job::{JobState, PasswordPopup};
use crate::keystore::{
    delete_key, load_contacts, load_keystore, save_contacts, save_key, ContactEntry, KeyEntry,
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
                let privkeys: Vec<[u8; 32]> =
                    self.keys.iter().map(|k| k.private_key).collect();
                if let Some(idx) = arsenic::arsenic_find_matching_key(&path, &privkeys) {
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

        // For decrypt mode: retrieve the selected private key (if any).
        let privkey = self
            .decrypt_key_index
            .and_then(|i| self.keys.get(i))
            .map(|k| k.private_key);

        let params = ArsenicParams {
            hdr_cipher: self.hdr_cipher,
            pld_cipher: self.pld_cipher,
            recipients,
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
                self.job = JobState::Idle;
                self.add_files(dropped);
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
