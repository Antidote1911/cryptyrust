use cryptyrust_core::{Algorithm, DeriveStrength};
use eframe::egui;
use std::path::PathBuf;

use crate::file_utils::{detect_mode, Mode};
use crate::job::{FileStatus, JobState, PasswordPopup};
use crate::ui::UI;

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
    pub algorithm: Algorithm,
    pub strength: DeriveStrength,
    pub show_about: bool,
    pub dark_mode: bool,
    pub pem_output: bool,
}

impl CryptyApp {
    pub fn new(storage: Option<&dyn eframe::Storage>, system_dark: bool) -> Self {
        let dark_mode = storage
            .and_then(|s| s.get_string("dark_mode"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(system_dark);

        let pem_output = storage
            .and_then(|s| s.get_string("pem_output"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        let algorithm = storage
            .and_then(|s| s.get_string("algorithm"))
            .and_then(|s| match s.as_str() {
                "xchacha20" => Some(Algorithm::XChaCha20Poly1305),
                "aes256gcm" => Some(Algorithm::Aes256Gcm),
                "aes256gcmsiv" => Some(Algorithm::Aes256GcmSiv),
                _ => None,
            })
            .unwrap_or(Algorithm::XChaCha20Poly1305);

        let strength = storage
            .and_then(|s| s.get_string("strength"))
            .and_then(|s| match s.as_str() {
                "interactive" => Some(DeriveStrength::Interactive),
                "moderate" => Some(DeriveStrength::Moderate),
                "sensitive" => Some(DeriveStrength::Sensitive),
                _ => None,
            })
            .unwrap_or(DeriveStrength::Moderate);

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
            algorithm,
            strength,
            show_about: false,
            dark_mode,
            pem_output,
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

    fn start_job(&mut self, ctx: egui::Context, password: String) {
        self.job.start(
            self.files.clone(),
            self.mode,
            self.algorithm,
            self.strength,
            password,
            self.pem_output,
            ctx,
        );
    }
}

impl eframe::App for CryptyApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string("dark_mode", self.dark_mode.to_string());
        storage.set_string(
            "algorithm",
            match self.algorithm {
                Algorithm::XChaCha20Poly1305 => "xchacha20",
                Algorithm::Aes256Gcm => "aes256gcm",
                Algorithm::Aes256GcmSiv => "aes256gcmsiv",
            }
            .to_string(),
        );
        storage.set_string("pem_output", self.pem_output.to_string());
        storage.set_string(
            "strength",
            match self.strength {
                DeriveStrength::Interactive => "interactive",
                DeriveStrength::Moderate => "moderate",
                DeriveStrength::Sensitive => "sensitive",
            }
            .to_string(),
        );
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
            ..
        } = &self.job
        {
            while let Ok((file_index, pct)) = receiver.try_recv() {
                progress.lock().unwrap().insert(file_index, pct);
            }
            ctx.request_repaint();

            let current = *current_file.lock().unwrap();
            if current == usize::MAX {
                // Job terminé, créer les statuses finaux
                let progress_map = progress.lock().unwrap();
                let mut statuses = Vec::new();

                for (i, _file) in processing_files.iter().enumerate() {
                    if progress_map.get(&i).is_some_and(|&p| p == 100) {
                        statuses.push(FileStatus::Success);
                    } else {
                        statuses.push(FileStatus::Failed("Unknown error".to_string()));
                    }
                }

                job_completed = Some((processing_files.clone(), statuses));
            }
        }

        // Mettre à jour l'état du job en dehors du if let
        if let Some((files, statuses)) = job_completed {
            self.job = JobState::Completed { files, statuses };
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        UI::render(self, ui);
    }
}
