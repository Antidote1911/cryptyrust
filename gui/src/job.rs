use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use rayon::prelude::*;

use cryptyrust_core::{
    main_routine, Algorithm, BenchMode, Config, Direction, DeriveStrength, HashMode, Secret, Ui,
};

use crate::file_utils::Mode;

#[derive(Clone, Debug)]
pub enum FileStatus {
    Pending,
    Processing,
    Success,
    Failed(String),  // message d'erreur
}

pub enum JobState {
    Idle,
    Running {
        progress: Arc<Mutex<HashMap<usize, i32>>>,
        receiver: Receiver<(usize, i32)>,
        current_file: Arc<Mutex<usize>>,
        processing_files: Vec<PathBuf>,
    },
    Completed {
        files: Vec<PathBuf>,
        statuses: Vec<FileStatus>,
    },
}

#[derive(PartialEq)]
pub enum PasswordPopup {
    Closed,
    Open,
}

struct ScaledProgress {
    tx: Sender<(usize, i32)>,
    file_index: usize,
}

impl Ui for ScaledProgress {
    fn output(&self, pct: i32) {
        let _ = self.tx.send((self.file_index, pct));
    }
}

impl JobState {
    pub fn start(
        &mut self,
        files: Vec<PathBuf>,
        mode: Mode,
        algo: Algorithm,
        strength: DeriveStrength,
        password: String,
        ctx: eframe::egui::Context,
    ) {
        let (tx, rx) = mpsc::channel::<(usize, i32)>();
        let progress = Arc::new(Mutex::new(HashMap::new()));
        let current_file = Arc::new(Mutex::new(0));
        let current_file_clone = current_file.clone();

        *self = JobState::Running {
            progress,
            receiver: rx,
            current_file,
            processing_files: files.clone(),
        };

        thread::spawn(move || {
            let completed_count = Arc::new(Mutex::new(0));
            let total_files = files.len();
            let file_statuses = Arc::new(Mutex::new(vec![FileStatus::Pending; total_files]));

            // Traitement parallèle avec Rayon
            let _results: Vec<bool> = files
                .clone()
                .into_par_iter()
                .enumerate()
                .map(|(i, path)| {
                    // Marquer comme en cours de traitement
                    file_statuses.lock().unwrap()[i] = FileStatus::Processing;

                    let in_file = path.to_string_lossy().to_string();
                    let out_file = match mode {
                        Mode::Encrypt => format!("{}.crypty", in_file),
                        Mode::Decrypt => {
                            if in_file.ends_with(".crypty") {
                                in_file.trim_end_matches(".crypty").to_string()
                            } else {
                                format!("{}.dec", in_file)
                            }
                        }
                    };

                    let sender = ScaledProgress {
                        tx: tx.clone(),
                        file_index: i,
                    };

                    let mut config = Config::new(
                        if mode == Mode::Encrypt {
                            Direction::Encrypt
                        } else {
                            Direction::Decrypt
                        },
                        algo,
                        strength,
                        Secret::new(password.clone()),
                        Some(in_file.clone()),
                        Some(out_file),
                        Box::new(sender),
                        HashMode::NoHash,
                        BenchMode::WriteToFilesystem,
                    );

                    let success = match main_routine(&mut config) {
                        Ok(_) => {
                            let _ = tx.send((i, 100));
                            file_statuses.lock().unwrap()[i] = FileStatus::Success;
                            true
                        }
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            file_statuses.lock().unwrap()[i] = FileStatus::Failed(error_msg);
                            false
                        }
                    };

                    // Incrémenter le compteur et vérifier si c'est le dernier
                    {
                        let mut completed = completed_count.lock().unwrap();
                        *completed += 1;
                        if *completed == total_files {
                            // Signaler la fin après un court délai
                            thread::spawn({
                                let ctx = ctx.clone();
                                let current_file_clone = current_file_clone.clone();
                                move || {
                                    thread::sleep(std::time::Duration::from_millis(500));
                                    *current_file_clone.lock().unwrap() = usize::MAX;
                                    ctx.request_repaint();
                                }
                            });
                        }
                    }

                    ctx.request_repaint();
                    success
                })
                .collect();

            // Les statuses sont maintenant stockés dans file_statuses
        });
    }
}