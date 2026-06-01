use std::collections::HashMap;
use rayon;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use arsenic::{
    arsenic_main_routine, arsenic_main_routine_with_key, arsenic_rekey, ArsenicParams, CoreErr,
    Direction, Secret, Ui,
};

use crate::file_utils::{create_unique_output_file, Mode};

#[derive(Clone, Debug)]
pub enum FileStatus {
    Pending,
    Processing,
    Success,
    Failed(String),
    Cancelled,
}

pub enum JobState {
    Idle,
    Running {
        progress: Arc<Mutex<HashMap<usize, i32>>>,
        receiver: Receiver<(usize, i32)>,
        current_file: Arc<Mutex<usize>>,
        processing_files: Vec<PathBuf>,
        file_statuses: Arc<Mutex<Vec<FileStatus>>>,
        success_label: String,
        cancel_flags: Vec<Arc<AtomicBool>>,
        cancel_all: Arc<AtomicBool>,
    },
    Completed {
        files: Vec<PathBuf>,
        statuses: Vec<FileStatus>,
        success_label: String,
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
    cancel_flag: Arc<AtomicBool>,
    cancel_all: Arc<AtomicBool>,
}

impl Ui for ScaledProgress {
    fn output(&self, pct: i32) {
        let _ = self.tx.send((self.file_index, pct));
    }

    fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed) || self.cancel_all.load(Ordering::Relaxed)
    }
}

impl JobState {
    /// Cancel all in-progress and pending files.
    pub fn cancel_all(&self) {
        if let JobState::Running { cancel_all, .. } = self {
            cancel_all.store(true, Ordering::Relaxed);
        }
    }

    pub fn start(
        &mut self,
        files: Vec<PathBuf>,
        mode: Mode,
        params: ArsenicParams,
        password: String,
        privkey: Option<[u8; 32]>,
        ctx: eframe::egui::Context,
    ) {
        let (tx, rx) = mpsc::channel::<(usize, i32)>();
        let progress = Arc::new(Mutex::new(HashMap::new()));
        let current_file = Arc::new(Mutex::new(0));
        let current_file_clone = current_file.clone();

        let total_files = files.len();
        let file_statuses = Arc::new(Mutex::new(vec![FileStatus::Pending; total_files]));
        let file_statuses_clone = file_statuses.clone();

        let cancel_flags: Vec<Arc<AtomicBool>> =
            (0..total_files).map(|_| Arc::new(AtomicBool::new(false))).collect();
        let cancel_all = Arc::new(AtomicBool::new(false));

        let cancel_flags_clone = cancel_flags.clone();
        let cancel_all_clone = cancel_all.clone();

        let success_label = match mode {
            Mode::Encrypt => "Encryption OK".to_string(),
            Mode::Decrypt => "Decryption OK".to_string(),
        };

        *self = JobState::Running {
            progress,
            receiver: rx,
            current_file,
            processing_files: files.clone(),
            file_statuses,
            success_label,
            cancel_flags,
            cancel_all,
        };

        thread::spawn(move || {
            // Process all files in parallel via Rayon.
            // rayon::scope blocks until every spawned task completes, then we
            // signal job completion with a single usize::MAX write.
            rayon::scope(|s| {
                for (i, path) in files.into_iter().enumerate() {
                    let tx = tx.clone();
                    let file_statuses_clone = file_statuses_clone.clone();
                    let cancel_flag = cancel_flags_clone[i].clone();
                    let cancel_all = cancel_all_clone.clone();
                    let params = params.clone();
                    let password = password.clone();
                    let ctx = ctx.clone();

                    s.spawn(move |_| {
                        if cancel_flag.load(Ordering::Relaxed)
                            || cancel_all.load(Ordering::Relaxed)
                        {
                            file_statuses_clone.lock().unwrap()[i] = FileStatus::Cancelled;
                            let _ = tx.send((i, 0));
                            ctx.request_repaint();
                            return;
                        }

                        file_statuses_clone.lock().unwrap()[i] = FileStatus::Processing;
                        let in_path = path.to_string_lossy().to_string();

                        let success = match mode {
                            Mode::Encrypt => match create_unique_output_file(&in_path, ".arsn") {
                                Err(e) => {
                                    report_error(&file_statuses_clone, i, e.to_string());
                                    false
                                }
                                Ok((out_path, _claim)) => {
                                    let ui: Box<dyn Ui> = Box::new(ScaledProgress {
                                        tx: tx.clone(),
                                        file_index: i,
                                        cancel_flag: cancel_flag.clone(),
                                        cancel_all: cancel_all.clone(),
                                    });
                                    match arsenic_main_routine(
                                        &Direction::Encrypt,
                                        Some(&in_path),
                                        Some(&out_path),
                                        &Secret::new(password),
                                        ui,
                                        Some(params),
                                    ) {
                                        Ok(_) => true,
                                        Err(CoreErr::Cancelled) => {
                                            let _ = std::fs::remove_file(&out_path);
                                            file_statuses_clone.lock().unwrap()[i] =
                                                FileStatus::Cancelled;
                                            false
                                        }
                                        Err(e) => {
                                            let _ = std::fs::remove_file(&out_path);
                                            report_error(&file_statuses_clone, i, e.to_string());
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
                                        report_error(&file_statuses_clone, i, e.to_string());
                                        false
                                    }
                                    Ok((out_path, _claim)) => {
                                        let ui: Box<dyn Ui> = Box::new(ScaledProgress {
                                            tx: tx.clone(),
                                            file_index: i,
                                            cancel_flag: cancel_flag.clone(),
                                            cancel_all: cancel_all.clone(),
                                        });
                                        let result = if let Some(pk) = privkey {
                                            arsenic_main_routine_with_key(
                                                Some(&in_path),
                                                Some(&out_path),
                                                &Secret::new(pk),
                                                ui,
                                            )
                                        } else {
                                            arsenic_main_routine(
                                                &Direction::Decrypt,
                                                Some(&in_path),
                                                Some(&out_path),
                                                &Secret::new(password),
                                                ui,
                                                None,
                                            )
                                        };
                                        match result {
                                            Ok(_) => true,
                                            Err(CoreErr::Cancelled) => {
                                                let _ = std::fs::remove_file(&out_path);
                                                file_statuses_clone.lock().unwrap()[i] =
                                                    FileStatus::Cancelled;
                                                false
                                            }
                                            Err(e) => {
                                                let _ = std::fs::remove_file(&out_path);
                                                report_error(
                                                    &file_statuses_clone,
                                                    i,
                                                    e.to_string(),
                                                );
                                                false
                                            }
                                        }
                                    }
                                }
                            }
                        };

                        if success {
                            let _ = tx.send((i, 100));
                            file_statuses_clone.lock().unwrap()[i] = FileStatus::Success;
                        }
                        ctx.request_repaint();
                    });
                }
            });

            // All files finished — signal completion after a brief display delay.
            thread::sleep(std::time::Duration::from_millis(500));
            *current_file_clone.lock().unwrap() = usize::MAX;
            ctx.request_repaint();
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

        let file_statuses = Arc::new(Mutex::new(vec![FileStatus::Pending; 1]));
        let file_statuses_clone = file_statuses.clone();

        let cancel_flags = vec![Arc::new(AtomicBool::new(false))];
        let cancel_all = Arc::new(AtomicBool::new(false));

        *self = JobState::Running {
            progress,
            receiver: rx,
            current_file,
            processing_files: vec![file.clone()],
            file_statuses,
            success_label: "Password changed".to_string(),
            cancel_flags,
            cancel_all,
        };

        thread::spawn(move || {
            file_statuses_clone.lock().unwrap()[0] = FileStatus::Processing;
            let result = do_change_pw_arsenic(&file, &old_pw, &new_pw, &tx);

            if result.is_ok() {
                let _ = tx.send((0, 100));
                file_statuses_clone.lock().unwrap()[0] = FileStatus::Success;
            } else if let Err(e) = result {
                file_statuses_clone.lock().unwrap()[0] = FileStatus::Failed(e.to_string());
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
            cancel_flag: Arc::new(AtomicBool::new(false)),
            cancel_all: Arc::new(AtomicBool::new(false)),
        },
    )?;
    Ok(())
}

fn report_error(statuses: &Arc<Mutex<Vec<FileStatus>>>, index: usize, msg: String) {
    statuses.lock().unwrap()[index] = FileStatus::Failed(msg);
}
