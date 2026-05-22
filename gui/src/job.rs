use std::collections::HashMap;
use std::fs::{remove_file, File};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use rayon::prelude::*;

use cryptyrust_core::{
    decrypt, encrypt, main_routine, Algorithm, BenchMode, Config, DeriveStrength, Direction,
    HashMode, Secret, Ui,
};

use crate::file_utils::{create_unique_output_file, Mode};
use crate::pem::{is_pem_cryptyrust_file, PemReader, PemWriter};

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
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        files: Vec<PathBuf>,
        mode: Mode,
        algo: Algorithm,
        strength: DeriveStrength,
        password: String,
        pem_output: bool,
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
                    let is_pem_file = is_pem_cryptyrust_file(&path);

                    let success = match mode {
                        Mode::Encrypt if pem_output => {
                            match create_unique_output_file(&in_path, ".crypty.pem") {
                                Err(e) => {
                                    report_error(&file_statuses, i, e.to_string());
                                    false
                                }
                                Ok((out_path, out_file)) => process_encrypt_pem(
                                    &in_path, &out_path, out_file, &password, algo, strength, &tx,
                                    i,
                                ),
                            }
                        }
                        Mode::Decrypt if is_pem_file => {
                            let (base, ext) = if in_path.ends_with(".crypty.pem") {
                                (in_path.trim_end_matches(".crypty.pem"), "")
                            } else if in_path.ends_with(".pem") {
                                (in_path.trim_end_matches(".pem"), "")
                            } else {
                                (in_path.as_str(), ".dec")
                            };
                            match create_unique_output_file(base, ext) {
                                Err(e) => {
                                    report_error(&file_statuses, i, e.to_string());
                                    false
                                }
                                Ok((out_path, out_file)) => process_decrypt_pem(
                                    &in_path, &out_path, out_file, &password, &tx, i,
                                ),
                            }
                        }
                        _ => {
                            // Binary path — use main_routine
                            let (base, ext) = match mode {
                                Mode::Encrypt => (in_path.as_str(), ".crypty"),
                                Mode::Decrypt => {
                                    if in_path.ends_with(".crypty") {
                                        (in_path.trim_end_matches(".crypty"), "")
                                    } else {
                                        (in_path.as_str(), ".dec")
                                    }
                                }
                            };
                            match create_unique_output_file(base, ext) {
                                Err(e) => {
                                    report_error(&file_statuses, i, e.to_string());
                                    false
                                }
                                Ok((out_path, _claim)) => {
                                    // _claim keeps the filename reserved while main_routine writes
                                    let sender = ScaledProgress {
                                        tx: tx.clone(),
                                        file_index: i,
                                    };
                                    let config = Config::new(
                                        if mode == Mode::Encrypt {
                                            Direction::Encrypt
                                        } else {
                                            Direction::Decrypt
                                        },
                                        algo,
                                        strength,
                                        Secret::new(password.clone()),
                                        Some(in_path.clone()),
                                        Some(out_path),
                                        Box::new(sender),
                                        HashMode::NoHash,
                                        BenchMode::WriteToFilesystem,
                                    );
                                    match main_routine(&config) {
                                        Ok(_) => {
                                            let _ = tx.send((i, 100));
                                            true
                                        }
                                        Err(e) => {
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
}

#[allow(clippy::too_many_arguments)]
fn process_encrypt_pem(
    in_path: &str,
    out_path: &str,
    out_file: File,
    password: &str,
    algo: Algorithm,
    strength: DeriveStrength,
    tx: &Sender<(usize, i32)>,
    file_index: usize,
) -> bool {
    let run = || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut in_file = File::open(in_path)?;
        let filesize = in_file.metadata()?.len();
        let mut writer = PemWriter::new(out_file, env!("CARGO_PKG_VERSION"))?;

        let ui: Box<dyn Ui> = Box::new(ScaledProgress {
            tx: tx.clone(),
            file_index,
        });
        encrypt(
            &mut in_file,
            &mut writer,
            &Secret::new(password.to_string()),
            &*ui,
            filesize,
            algo,
            strength,
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        )?;
        writer.finish()?;
        Ok(())
    };

    match run() {
        Ok(_) => true,
        Err(e) => {
            let _ = remove_file(out_path);
            eprintln!("PEM encrypt error: {}", e);
            false
        }
    }
}

fn process_decrypt_pem(
    in_path: &str,
    out_path: &str,
    mut out_file: File,
    password: &str,
    tx: &Sender<(usize, i32)>,
    file_index: usize,
) -> bool {
    let mut run = || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pem_size = File::open(in_path)?.metadata()?.len();
        let approx_size = (pem_size * 3) / 4;
        let mut reader = PemReader::new(std::path::Path::new(in_path))?;

        let ui: Box<dyn Ui> = Box::new(ScaledProgress {
            tx: tx.clone(),
            file_index,
        });
        decrypt(
            &mut reader,
            &mut out_file,
            &Secret::new(password.to_string()),
            &*ui,
            approx_size,
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        )?;
        Ok(())
    };

    match run() {
        Ok(_) => true,
        Err(e) => {
            let _ = remove_file(out_path);
            eprintln!("PEM decrypt error: {}", e);
            false
        }
    }
}

fn report_error(statuses: &Arc<Mutex<Vec<FileStatus>>>, index: usize, msg: String) {
    statuses.lock().unwrap()[index] = FileStatus::Failed(msg);
}
