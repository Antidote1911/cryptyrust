use std::collections::HashMap;
use rayon;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use arsenic::{
    arsenic_main_routine, arsenic_main_routine_with_key, arsenic_rekey, ArsenicParams, CoreErr,
    Direction, Secret, Ui,
    keystore::KeyEntry,
    armor, dearmor, decrypt_arsenic, decrypt_arsenic_with_key,
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
        armor: bool,
        password: String,
        privkey: Option<KeyEntry>,
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
                    let privkey = privkey.clone();
                    let ctx = ctx.clone();
                    let armor = armor;

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
                                    let result = arsenic_main_routine(
                                        &Direction::Encrypt,
                                        Some(&in_path),
                                        Some(&out_path),
                                        &Secret::new(password),
                                        ui,
                                        Some(params),
                                    );
                                    match result {
                                        Ok(_) => {
                                            // Post-processing: ASCII armor if requested.
                                            if armor {
                                                match apply_armor(&out_path) {
                                                    Ok(()) => {},
                                                    Err(e) => {
                                                        report_error(&file_statuses_clone, i, e);
                                                        // armor failed; keep the unarmored file
                                                    }
                                                }
                                            }
                                            true
                                        }
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
                                let base = if in_path.ends_with(".arsn.armor") {
                                    in_path.trim_end_matches(".arsn.armor").to_string()
                                } else if in_path.ends_with(".arsn") {
                                    in_path.trim_end_matches(".arsn").to_string()
                                } else {
                                    let parent = path.parent().unwrap_or_else(|| Path::new(""));
                                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                    parent.join(format!("decrypted_{}", name)).to_string_lossy().into_owned()
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

                                        // Check for ASCII armor and dearmor if needed.
                                        let result: Result<(), CoreErr> = match try_dearmor_file(&in_path) {
                                            Ok(Some(ct)) => {
                                                decrypt_bytes_to_file(ct, &out_path, &password, privkey.as_ref(), ui)
                                                    .map(|_| ())
                                            }
                                            Ok(None) => {
                                                // Binary .arsn file — standard path.
                                                if let Some(ref key) = privkey {
                                                    arsenic_main_routine_with_key(
                                                        Some(&in_path), Some(&out_path), key, ui,
                                                    ).map(|_| ())
                                                } else {
                                                    arsenic_main_routine(
                                                        &Direction::Decrypt,
                                                        Some(&in_path), Some(&out_path),
                                                        &Secret::new(password), ui, None,
                                                    ).map(|_| ())
                                                }
                                            }
                                            Err(e) => Err(e),
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

/// Read the file; if it looks like ASCII armor, dearmor and return `Some(bytes)`.
/// Returns `Ok(None)` for binary files, `Err` on read/dearmor failure.
fn try_dearmor_file(path: &str) -> Result<Option<Vec<u8>>, CoreErr> {
    let data = std::fs::read(path).map_err(CoreErr::IOError)?;
    if data.starts_with(b"-----BEGIN ARSENIC") {
        let s = std::str::from_utf8(&data)
            .map_err(|_| CoreErr::DecryptFail("armor file is not valid UTF-8".into()))?;
        let ct = dearmor(s)?;
        Ok(Some(ct))
    } else {
        Ok(None)
    }
}

/// Decrypt a ciphertext byte slice to a file, trying the keypair first then the password.
fn decrypt_bytes_to_file(
    ct: Vec<u8>,
    out_path: &str,
    password: &str,
    key: Option<&KeyEntry>,
    ui: Box<dyn Ui>,
) -> Result<arsenic::EnvelopeMetadata, CoreErr> {
    use std::io::Cursor;
    let filesize = ct.len() as u64;
    let mut input = Cursor::new(&ct);
    let mut output = std::fs::File::create(out_path).map_err(CoreErr::IOError)?;
    if let Some(k) = key {
        let privkey = Secret::new(k.private_key);
        decrypt_arsenic_with_key(&mut input, &mut output, &privkey, &k.mlkem_seed, &*ui, filesize)
    } else {
        decrypt_arsenic(&mut input, &mut output, &Secret::new(password.to_string()), &*ui, filesize)
    }
}

/// ASCII-armor `path` in-place: reads the binary file, armors it, writes to
/// `path.armor`, then removes the original `.arsn` file.
fn apply_armor(path: &str) -> Result<(), String> {
    let ct = std::fs::read(path).map_err(|e| format!("armor read: {e}"))?;
    let armored = armor(&ct);
    let armor_path = format!("{path}.armor");
    std::fs::write(&armor_path, armored.as_bytes())
        .map_err(|e| format!("armor write: {e}"))?;
    std::fs::remove_file(path).map_err(|e| format!("armor cleanup: {e}"))?;
    Ok(())
}
