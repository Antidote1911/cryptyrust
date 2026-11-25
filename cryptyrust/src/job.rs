use crate::i18n::tr;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use arsenic::{
    armor, arsenic_main_routine, arsenic_main_routine_with_key, arsenic_read_params,
    arsenic_rekey, dearmor, decrypt_arsenic, decrypt_arsenic_with_key, find_decrypting_key,
    keystore::KeyEntry, ArsenicParams, CoreErr, Direction, HybridPrivKey, Secret, Ui,
};

use crate::file_utils::{create_unique_output_file, is_armored_file, Mode};

/// Upper bound on the Argon2id memory used by files processed at the same
/// time, in KiB. Each file runs its own key derivation (256 MiB or 1 GiB), so
/// the number of parallel files is capped to keep the total under this budget.
const KDF_RAM_BUDGET_KIB: u32 = 2 * 1024 * 1024;

/// Hard cap on files processed at the same time. The library already spreads
/// the blocks of one file over every core (holding up to 128 MiB of data per
/// file), so more files in parallel would only add memory pressure.
const MAX_PARALLEL_FILES: usize = 4;

/// Lock a mutex shared with the job threads. A poisoned lock (a worker
/// panicked) still holds usable data, so the UI keeps running.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

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
        /// `usize::MAX` once every file is finished.
        current_file: Arc<Mutex<usize>>,
        processing_files: Vec<PathBuf>,
        file_statuses: Arc<Mutex<Vec<FileStatus>>>,
        success_label: String,
        cancel_flags: Vec<Arc<AtomicBool>>,
        cancel_all: Arc<AtomicBool>,
        /// False for operations that cannot be interrupted (password change).
        cancellable: bool,
    },
    Completed {
        files: Vec<PathBuf>,
        statuses: Vec<FileStatus>,
        success_label: String,
    },
}

#[derive(PartialEq, Eq)]
pub enum PasswordPopup {
    Closed,
    Open,
    ChangePw,
}

struct JobProgress {
    tx: Sender<(usize, i32)>,
    file_index: usize,
    cancel_flag: Arc<AtomicBool>,
    cancel_all: Arc<AtomicBool>,
}

impl Ui for JobProgress {
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
        if let Self::Running { cancel_all, cancellable: true, .. } = self {
            cancel_all.store(true, Ordering::Relaxed);
        }
    }

    /// Encrypt or decrypt `files` in the background.
    ///
    /// Decryption tries `keys` first, file by file: a file with a keyslot for
    /// one of them is decrypted with that keypair, any other file falls back
    /// to `password`.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        files: Vec<PathBuf>,
        mode: Mode,
        params: ArsenicParams,
        armor: bool,
        password: String,
        keys: Vec<KeyEntry>,
        ctx: eframe::egui::Context,
    ) {
        let (tx, rx) = mpsc::channel::<(usize, i32)>();
        let current_file = Arc::new(Mutex::new(0));
        let file_statuses = Arc::new(Mutex::new(vec![FileStatus::Pending; files.len()]));
        let cancel_flags: Vec<Arc<AtomicBool>> =
            (0..files.len()).map(|_| Arc::new(AtomicBool::new(false))).collect();
        let cancel_all = Arc::new(AtomicBool::new(false));

        let success_label = match mode {
            Mode::Encrypt => tr("Encryption OK").to_string(),
            Mode::Decrypt => tr("Decryption OK").to_string(),
        };

        *self = Self::Running {
            progress: Arc::new(Mutex::new(HashMap::new())),
            receiver: rx,
            current_file: current_file.clone(),
            processing_files: files.clone(),
            file_statuses: file_statuses.clone(),
            success_label,
            cancel_flags: cancel_flags.clone(),
            cancel_all: cancel_all.clone(),
            cancellable: true,
        };

        thread::spawn(move || {
            // One copy of the password for the whole job, wiped when it ends.
            let password = Secret::new(password);
            let next = AtomicUsize::new(0);
            let set_status = |i: usize, status: FileStatus| {
                lock(&file_statuses)[i] = status;
                ctx.request_repaint();
            };

            // A bounded set of workers takes the files in order.
            thread::scope(|s| {
                for _ in 0..max_parallel_files(mode, &params, &files) {
                    s.spawn(|| loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = files.get(i) else { break };

                        if cancel_flags[i].load(Ordering::Relaxed)
                            || cancel_all.load(Ordering::Relaxed)
                        {
                            set_status(i, FileStatus::Cancelled);
                            continue;
                        }

                        set_status(i, FileStatus::Processing);
                        let ui: Box<dyn Ui> = Box::new(JobProgress {
                            tx: tx.clone(),
                            file_index: i,
                            cancel_flag: cancel_flags[i].clone(),
                            cancel_all: cancel_all.clone(),
                        });
                        // A panic in one file must not leave the whole job
                        // (and the UI) waiting forever: report it as a failure.
                        let result = panic::catch_unwind(AssertUnwindSafe(|| match mode {
                            Mode::Encrypt => encrypt_file(path, armor, &password, &params, ui),
                            Mode::Decrypt => decrypt_file(path, &password, &keys, ui),
                        }))
                        .unwrap_or_else(|_| {
                            Err(CoreErr::IOError(std::io::Error::other(
                                tr("internal error while processing this file"),
                            )))
                        });
                        match result {
                            Ok(()) => {
                                let _ = tx.send((i, 100));
                                set_status(i, FileStatus::Success);
                            }
                            Err(CoreErr::Cancelled) => set_status(i, FileStatus::Cancelled),
                            Err(e) => set_status(i, FileStatus::Failed(crate::i18n::core_err(&e))),
                        }
                    });
                }
            });

            // All files finished — signal completion after a brief display delay.
            thread::sleep(std::time::Duration::from_millis(500));
            *lock(&current_file) = usize::MAX;
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
        let old_pw = Secret::new(old_pw);
        let new_pw = Secret::new(new_pw);
        let (tx, rx) = mpsc::channel::<(usize, i32)>();
        let current_file = Arc::new(Mutex::new(0usize));
        let file_statuses = Arc::new(Mutex::new(vec![FileStatus::Pending; 1]));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_all = Arc::new(AtomicBool::new(false));

        *self = Self::Running {
            progress: Arc::new(Mutex::new(HashMap::new())),
            receiver: rx,
            current_file: current_file.clone(),
            processing_files: vec![file.clone()],
            file_statuses: file_statuses.clone(),
            success_label: tr("Password changed").to_string(),
            cancel_flags: vec![cancel_flag.clone()],
            cancel_all: cancel_all.clone(),
            // The header rewrite is not interruptible: no Stop button is shown.
            cancellable: false,
        };

        thread::spawn(move || {
            lock(&file_statuses)[0] = FileStatus::Processing;
            let ui = JobProgress { tx: tx.clone(), file_index: 0, cancel_flag, cancel_all };
            let status = match arsenic_rekey(&file, &old_pw, &new_pw, &ui) {
                Ok(()) => {
                    let _ = tx.send((0, 100));
                    FileStatus::Success
                }
                Err(e) => FileStatus::Failed(crate::i18n::core_err(&e)),
            };
            lock(&file_statuses)[0] = status;

            thread::sleep(std::time::Duration::from_millis(500));
            *lock(&current_file) = usize::MAX;
            ctx.request_repaint();
        });
    }
}

/// How many files may be processed at once without exceeding
/// [`KDF_RAM_BUDGET_KIB`] of Argon2id memory.
fn max_parallel_files(mode: Mode, params: &ArsenicParams, files: &[PathBuf]) -> usize {
    // Unknown cost (armored or unreadable header): assume the largest preset.
    const UNKNOWN_M_COST_KIB: u32 = 1024 * 1024;
    let m_cost = match mode {
        Mode::Encrypt => params.m_cost,
        Mode::Decrypt => files
            .iter()
            .map(|p| arsenic_read_params(p).map_or(UNKNOWN_M_COST_KIB, |p| p.m_cost))
            .max()
            .unwrap_or(UNKNOWN_M_COST_KIB),
    };
    let by_memory = (KDF_RAM_BUDGET_KIB / m_cost.max(1)).max(1) as usize;
    let cores = thread::available_parallelism().map_or(1, usize::from);
    by_memory.min(cores).min(MAX_PARALLEL_FILES).min(files.len()).max(1)
}

/// Claim `base + ext` (or a numbered variant) for writing.
fn claim_output(base: &str, ext: &str) -> Result<(String, std::fs::File), CoreErr> {
    create_unique_output_file(base, ext).map_err(CoreErr::IOError)
}

/// Encrypt `path` to `path.arsn` (or `path.arsn.armor`). The final name is
/// claimed first, so an existing output is never overwritten.
fn encrypt_file(
    path: &Path,
    armor: bool,
    password: &Secret<String>,
    params: &ArsenicParams,
    ui: Box<dyn Ui>,
) -> Result<(), CoreErr> {
    let in_path = path.to_string_lossy().into_owned();
    let ext = if armor { ".arsn.armor" } else { ".arsn" };
    let (out_path, _claim) = claim_output(&in_path, ext)?;

    let result = if armor {
        encrypt_armored(&in_path, &out_path, password, ui, params.clone())
    } else {
        arsenic_main_routine(
            &Direction::Encrypt,
            Some(&in_path),
            Some(&out_path),
            password,
            ui,
            Some(params.clone()),
        )
        .map(|_| ())
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&out_path);
    }
    result
}

/// Decrypt `path` next to itself, with a matching keypair from `keys` if there
/// is one, otherwise with `password`.
fn decrypt_file(
    path: &Path,
    password: &Secret<String>,
    keys: &[KeyEntry],
    ui: Box<dyn Ui>,
) -> Result<(), CoreErr> {
    let in_path = path.to_string_lossy().into_owned();
    let base = in_path
        .strip_suffix(".arsn.armor")
        .or_else(|| in_path.strip_suffix(".arsn"))
        .map_or_else(
            || {
                let parent = path.parent().unwrap_or_else(|| Path::new(""));
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                parent.join(format!("decrypted_{name}")).to_string_lossy().into_owned()
            },
            str::to_string,
        );
    let (out_path, _claim) = claim_output(&base, "")?;

    let result = if is_armored_file(path) {
        decrypt_armored(path, &out_path, password, keys, &*ui)
    } else {
        let key = std::fs::File::open(path).ok().and_then(|mut f| matching_key(&mut f, keys));
        match key {
            Some(key) => {
                arsenic_main_routine_with_key(Some(&in_path), Some(&out_path), key, ui).map(|_| ())
            }
            None => require_password(password).and_then(|()| {
                arsenic_main_routine(
                    &Direction::Decrypt,
                    Some(&in_path),
                    Some(&out_path),
                    password,
                    ui,
                    None,
                )
                .map(|_| ())
            }),
        }
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&out_path);
    }
    result
}

/// The keypair in `keys` that opens one of the file's keyslots, if any.
fn matching_key<'k, R: Read>(input: &mut R, keys: &'k [KeyEntry]) -> Option<&'k KeyEntry> {
    let hybrid: Vec<HybridPrivKey<'_>> = keys
        .iter()
        .map(|k| HybridPrivKey { x25519_sk: &k.private_key, mlkem_seed: &k.mlkem_seed })
        .collect();
    let idx = find_decrypting_key(input, &hybrid).ok().flatten()?;
    keys.get(idx)
}

fn require_password(password: &Secret<String>) -> Result<(), CoreErr> {
    if password.expose().is_empty() {
        return Err(CoreErr::DecryptFail(
            tr("no stored keypair matches this file — a password is required.").into(),
        ));
    }
    Ok(())
}

/// Dearmor `path` in memory and decrypt it to `out_path`.
fn decrypt_armored(
    path: &Path,
    out_path: &str,
    password: &Secret<String>,
    keys: &[KeyEntry],
    ui: &dyn Ui,
) -> Result<(), CoreErr> {
    let data = std::fs::read(path)?;
    let text = std::str::from_utf8(&data)
        .map_err(|_| CoreErr::DecryptFail(tr("armor file is not valid UTF-8").into()))?;
    let ct = dearmor(text)?;
    let filesize = ct.len() as u64;

    let key = matching_key(&mut Cursor::new(&ct), keys);
    if key.is_none() {
        require_password(password)?;
    }
    let mut input = Cursor::new(&ct);
    let mut output = std::fs::File::create(out_path)?;
    match key {
        Some(k) => {
            let privkey = Secret::new(k.private_key);
            decrypt_arsenic_with_key(&mut input, &mut output, &privkey, &k.mlkem_seed, ui, filesize)
        }
        None => decrypt_arsenic(&mut input, &mut output, password, ui, filesize),
    }
    .map(|_| ())
}

/// Encrypt `in_path` and write the ASCII-armored result to `out_path`.
///
/// `out_path` must already be claimed by the caller. The binary ciphertext goes
/// to a temporary file in the same directory, removed on every exit path; any
/// failure (including the armor step) is returned so the caller reports it.
fn encrypt_armored(
    in_path: &str,
    out_path: &str,
    password: &Secret<String>,
    ui: Box<dyn Ui>,
    params: ArsenicParams,
) -> Result<(), CoreErr> {
    let dir = match Path::new(out_path).parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".cryptyrust-")
        .suffix(".arsn.tmp")
        .tempfile_in(dir)?;
    let tmp_path = tmp.path().to_string_lossy().into_owned();
    arsenic_main_routine(
        &Direction::Encrypt,
        Some(in_path),
        Some(&tmp_path),
        password,
        ui,
        Some(params),
    )?;
    let ct = std::fs::read(tmp.path())?;
    std::fs::write(out_path, armor(&ct).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arsenic::ArsenicStrength;
    use std::time::{Duration, Instant};

    /// Run a job to completion and return the final statuses.
    fn run_job(
        files: &[PathBuf],
        mode: Mode,
        params: ArsenicParams,
        armor: bool,
        password: &str,
        keys: Vec<KeyEntry>,
    ) -> Vec<FileStatus> {
        let mut job = JobState::Idle;
        job.start(
            files.to_vec(),
            mode,
            params,
            armor,
            password.to_string(),
            keys,
            eframe::egui::Context::default(),
        );
        let JobState::Running { current_file, file_statuses, .. } = &job else {
            panic!("job should be running");
        };
        let deadline = Instant::now() + Duration::from_secs(300);
        while *current_file.lock().unwrap() != usize::MAX {
            assert!(Instant::now() < deadline, "job timed out");
            thread::sleep(Duration::from_millis(50));
        }
        let statuses = file_statuses.lock().unwrap().clone();
        statuses
    }

    fn interactive() -> ArsenicParams {
        ArsenicParams::from(ArsenicStrength::Interactive)
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn armored_encrypt_never_overwrites_previous_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let plain = dir.path().join("msg.txt");
        std::fs::write(&plain, b"armored message").unwrap();
        let files = [plain];

        let statuses = run_job(&files, Mode::Encrypt, interactive(), true, "first_password", vec![]);
        assert!(matches!(statuses[0], FileStatus::Success), "{statuses:?}");
        let first = dir.path().join("msg.txt.arsn.armor");
        let first_content = std::fs::read_to_string(&first).unwrap();
        assert!(first_content.starts_with("-----BEGIN ARSENIC"));

        let statuses = run_job(&files, Mode::Encrypt, interactive(), true, "second_password", vec![]);
        assert!(matches!(statuses[0], FileStatus::Success), "{statuses:?}");
        assert_eq!(
            listing(dir.path()),
            ["msg.txt", "msg.txt (1).arsn.armor", "msg.txt.arsn.armor"]
        );
        assert_eq!(std::fs::read_to_string(&first).unwrap(), first_content);
    }

    /// A batch mixing a file encrypted for a stored keypair and a
    /// password-only file: each one is opened with what fits it.
    #[test]
    fn decrypt_picks_key_or_password_per_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = KeyEntry::generate("alice".into());
        let for_key = dir.path().join("for_key.txt");
        let for_pw = dir.path().join("for_pw.txt");
        std::fs::write(&for_key, b"key message").unwrap();
        std::fs::write(&for_pw, b"password message").unwrap();

        // Recipient-only file (random throwaway password, as the GUI does).
        let with_recipient =
            ArsenicParams { recipients: vec![key.as_recipient()], ..interactive() };
        let s = run_job(
            std::slice::from_ref(&for_key), Mode::Encrypt, with_recipient, false, "throwaway-secret", vec![],
        );
        assert!(matches!(s[0], FileStatus::Success), "{s:?}");
        // Password-only file, armored to cover that path too.
        let s = run_job(std::slice::from_ref(&for_pw), Mode::Encrypt, interactive(), true, "the_password", vec![]);
        assert!(matches!(s[0], FileStatus::Success), "{s:?}");
        std::fs::remove_file(&for_key).unwrap();
        std::fs::remove_file(&for_pw).unwrap();

        let encrypted =
            [dir.path().join("for_key.txt.arsn"), dir.path().join("for_pw.txt.arsn.armor")];

        // Without a password only the keypair file can be opened; the other
        // one fails cleanly and leaves no output behind.
        let s = run_job(&encrypted, Mode::Decrypt, interactive(), false, "", vec![key.clone()]);
        assert!(matches!(s[0], FileStatus::Success), "{s:?}");
        assert!(
            matches!(&s[1], FileStatus::Failed(e) if e.contains("password is required")),
            "{s:?}"
        );
        assert_eq!(std::fs::read(&for_key).unwrap(), b"key message");
        assert!(!for_pw.exists());
        std::fs::remove_file(&for_key).unwrap();

        // With the password both succeed.
        let s = run_job(&encrypted, Mode::Decrypt, interactive(), false, "the_password", vec![key]);
        assert!(s.iter().all(|x| matches!(x, FileStatus::Success)), "{s:?}");
        assert_eq!(std::fs::read(&for_key).unwrap(), b"key message");
        assert_eq!(std::fs::read(&for_pw).unwrap(), b"password message");
    }

    #[test]
    fn parallel_files_are_bounded_by_argon2_memory() {
        let files: Vec<PathBuf> = (0..64).map(|i| PathBuf::from(format!("f{i}"))).collect();
        let cores = thread::available_parallelism().map_or(1, usize::from);
        let sensitive = ArsenicParams::from(ArsenicStrength::Sensitive);

        assert_eq!(max_parallel_files(Mode::Encrypt, &sensitive, &files), 2.min(cores));
        assert_eq!(max_parallel_files(Mode::Encrypt, &interactive(), &files), 4.min(cores));
        // Never more workers than files, never zero.
        assert_eq!(max_parallel_files(Mode::Encrypt, &interactive(), &files[..1]), 1);
        assert_eq!(max_parallel_files(Mode::Encrypt, &interactive(), &[]), 1);
        // Unreadable headers are assumed to need the largest preset.
        assert_eq!(max_parallel_files(Mode::Decrypt, &interactive(), &files), 2.min(cores));
    }
}
