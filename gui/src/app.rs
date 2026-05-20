use eframe::egui;
use std::path::PathBuf;
use cryptyrust_core::{Algorithm, DeriveStrength};

use crate::job::{JobState, PasswordPopup, FileStatus};
use crate::file_utils::{detect_mode, Mode};
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
}

impl Default for CryptyApp {
    fn default() -> Self {
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
            algorithm: Algorithm::XChaCha20Poly1305,
            strength: DeriveStrength::Moderate,
            show_about: false,
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
            ctx,
        );
    }
}

impl eframe::App for CryptyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle drag & drop
        if self.popup == PasswordPopup::Closed && matches!(self.job, JobState::Idle | JobState::Completed { .. }) {
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
                    if progress_map.get(&i).map_or(false, |&p| p == 100) {
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