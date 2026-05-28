use cryptyrust_core::{
    bench_cipher_combinations, ArsenicParams, ArsenicStrength, CipherBenchResult, CipherId,
    Compression, Ui, ZSTD_DEFAULT_LEVEL,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use crate::file_utils::{cipher_from_key, cipher_to_key, detect_mode, Mode};
use crate::job::{JobState, PasswordPopup};
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
    pub arsenic_strength: ArsenicStrength,
    /// Cipher used to encrypt the key-envelope in the header (encryption only).
    pub hdr_cipher: CipherId,
    /// Cipher used to encrypt each payload block (encryption only).
    pub pld_cipher: CipherId,
    /// Whether to compress plaintext with zstd before encryption (disabled by default).
    pub compress: bool,
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

        let compress = storage
            .and_then(|s| s.get_string("compress"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

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
            arsenic_strength,
            hdr_cipher,
            pld_cipher,
            compress,
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
        }
    }
}

impl CryptyApp {
    pub fn add_files(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        for p in paths {
            if !self.files.contains(&p) {
                self.files.push(p);
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
        self.popup = PasswordPopup::Open;
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
        if self.pw.is_empty() {
            self.pw_error = Some("Password cannot be empty.".into());
            return;
        }
        if self.mode == Mode::Encrypt && self.pw != self.pw_confirm {
            self.pw_error = Some("Passwords do not match.".into());
            return;
        }
        let password = self.pw.clone();
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

    fn start_job(&mut self, ctx: egui::Context, password: String) {
        let params = ArsenicParams {
            hdr_cipher: self.hdr_cipher,
            pld_cipher: self.pld_cipher,
            compression: if self.compress {
                Compression::Zstd(ZSTD_DEFAULT_LEVEL)
            } else {
                Compression::None
            },
            ..ArsenicParams::from(self.arsenic_strength)
        };
        self.job
            .start(self.files.clone(), self.mode, params, password, ctx);
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
        storage.set_string("compress", self.compress.to_string());
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
        } = &self.job
        {
            while let Ok((file_index, pct)) = receiver.try_recv() {
                progress.lock().unwrap().insert(file_index, pct);
            }
            // Cap the repaint rate to ~20 fps while a job is running.
            // Without this, egui spins at maximum rate and burns a full CPU core,
            // competing with the Rayon threads doing block-level encryption.
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
