use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use rayon::prelude::*;

use cryptyrust_core::{
    arsenic_main_routine, arsenic_rekey, ArsenicParams, Direction, Secret, Ui,
};

use crate::file_utils::{create_unique_output_file, Mode};

#[derive(Clone, Debug)]
pub enum FileStatus {
    Pending,
    Processing,
    Success,
    Failed(String),
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
    ChangePw,
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
        params: ArsenicParams,
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

            let _results: Vec<bool> = files
                .clone()
                .into_par_iter()
                .enumerate()
                .map(|(i, path)| {
                    file_statuses.lock().unwrap()[i] = FileStatus::Processing;

                    let in_path = path.to_string_lossy().to_string();

                    let success = match mode {
                        Mode::Encrypt => match create_unique_output_file(&in_path, ".arsn") {
                            Err(e) => {
                                report_error(&file_statuses, i, e.to_string());
                                false
                            }
                            Ok((out_path, _claim)) => {
                                let ui: Box<dyn Ui> = Box::new(ScaledProgress {
                                    tx: tx.clone(),
                                    file_index: i,
                                });
                                let params = params.clone();
                                match arsenic_main_routine(
                                    &Direction::Encrypt,
                                    Some(&in_path),
                                    Some(&out_path),
                                    &Secret::new(password.clone()),
                                    ui,
                                    Some(params),
                                ) {
                                    Ok(_) => {
                                        let _ = tx.send((i, 100));
                                        true
                                    }
                                    Err(e) => {
                                        let _ = std::fs::remove_file(&out_path);
                                        report_error(&file_statuses, i, e.to_string());
                                        false
                                    }
                                }
                            }
                        },
                        Mode::Decrypt => {
                            let base = if in_path.ends_with(".arsn") {
                                in_path.trim_end_matches(".arsn").to_string()
                            } else {
                                format!("decrypted_{}", in_path)
                            };
                            match create_unique_output_file(&base, "") {
                                Err(e) => {
                                    report_error(&file_statuses, i, e.to_string());
                                    false
                                }
                                Ok((out_path, _claim)) => {
                                    let ui: Box<dyn Ui> = Box::new(ScaledProgress {
                                        tx: tx.clone(),
                                        file_index: i,
                                    });
                                    match arsenic_main_routine(
                                        &Direction::Decrypt,
                                        Some(&in_path),
                                        Some(&out_path),
                                        &Secret::new(password.clone()),
                                        ui,
                                        None,
                                    ) {
                                        Ok(_) => {
                                            let _ = tx.send((i, 100));
                                            true
                                        }
                                        Err(e) => {
                                            let _ = std::fs::remove_file(&out_path);
                                            report_error(&file_statuses, i, e.to_string());
                                            false
                                        }
                                    }
                                }
                            }
                        }
                    };

                    if success {
                        let _ = tx.send((i, 100));
                        file_statuses.lock().unwrap()[i] = FileStatus::Success;
                    }

                    {
                        let mut completed = completed_count.lock().unwrap();
                        *completed += 1;
                        if *completed == total_files {
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
        });
    }

    pub fn start_change_pw(
        &mut self,
        file: PathBuf,
        old_pw: String,
        new_pw: String,
        ctx: eframe::egui::Context,
    ) {
        let (tx, rx) = mpsc::channel::<(usize, i32)>();
        let progress = Arc::new(Mutex::new(HashMap::new()));
        let current_file = Arc::new(Mutex::new(0usize));
        let current_file_clone = current_file.clone();

        *self = JobState::Running {
            progress,
            receiver: rx,
            current_file,
            processing_files: vec![file.clone()],
        };

        thread::spawn(move || {
            let result = do_change_pw_arsenic(&file, &old_pw, &new_pw, &tx);

            if result.is_ok() {
                let _ = tx.send((0, 100));
            } else if let Err(e) = result {
                eprintln!("change_password error: {}", e);
            }

            thread::sleep(std::time::Duration::from_millis(500));
            *current_file_clone.lock().unwrap() = usize::MAX;
            ctx.request_repaint();
        });
    }
}

fn do_change_pw_arsenic(
    path: &std::path::Path,
    old_pw: &str,
    new_pw: &str,
    tx: &Sender<(usize, i32)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    arsenic_rekey(
        path,
        &Secret::new(old_pw.to_string()),
        &Secret::new(new_pw.to_string()),
        &ScaledProgress {
            tx: tx.clone(),
            file_index: 0,
        },
    )?;
    Ok(())
}

fn report_error(statuses: &Arc<Mutex<Vec<FileStatus>>>, index: usize, msg: String) {
    statuses.lock().unwrap()[index] = FileStatus::Failed(msg);
}
