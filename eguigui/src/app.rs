use eframe::egui;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use cryptyrust_core::{
    main_routine, Config, Direction, Ui,
    Algorithm, Secret, HashMode, BenchMode, DeriveStrength,
};

// ── Magic number Cryptyrust : "CRYP" (0x43 0x52 0x59 0x50) ─────────
const CRYPTYRUST_MAGIC: [u8; 4] = [0x43, 0x52, 0x59, 0x50];

/// Retourne true si le fichier commence par la signature Cryptyrust.
fn is_cryptyrust_file(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut magic = [0u8; 4];
    matches!(f.read_exact(&mut magic), Ok(_) if magic == CRYPTYRUST_MAGIC)
}

/// Détecte le mode à partir d'une liste de fichiers.
fn detect_mode(files: &[PathBuf]) -> Option<Mode> {
    if files.is_empty() { return Some(Mode::Encrypt); }
    let encrypted_count = files.iter().filter(|p| is_cryptyrust_file(p)).count();
    if encrypted_count == files.len()  { Some(Mode::Decrypt) }
    else if encrypted_count == 0       { Some(Mode::Encrypt) }
    else                               { None }               // mélange
}

// ── Trait Ui qui envoie la progression via channel ─────────────────
struct ChannelProgress {
    sender: Sender<i32>,
}

impl Ui for ChannelProgress {
    fn output(&self, percentage: i32) {
        let _ = self.sender.send(percentage);
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Mode { Encrypt, Decrypt }

// ── État de la fenêtre modale de mot de passe ──────────────────────
#[derive(PartialEq, Clone, Copy, Debug)]
enum ModalState {
    None,
    Encrypt,
    Decrypt,
}

// ── État du traitement en cours ────────────────────────────────────
enum JobState {
    Idle,
    Running {
        progress: Arc<Mutex<i32>>,
        receiver: Receiver<i32>,
    },
    Done(Result<String, String>),
}

pub struct CryptyApp {
    mode:             Mode,
    mixed_files:      bool,
    files:            Vec<PathBuf>,
    // États pour la fenêtre de mot de passe
    modal_state:      ModalState,
    password_input:   String,
    password_confirm: String,
    password_error:   Option<String>,
    show_pass:        bool,
    
    algorithm:        Algorithm,
    strength:         DeriveStrength,
    job:              JobState,
}

impl Default for CryptyApp {
    fn default() -> Self {
        Self {
            mode:             Mode::Encrypt,
            mixed_files:      false,
            files:            vec![],
            modal_state:      ModalState::None,
            password_input:   String::new(),
            password_confirm: String::new(),
            password_error:   None,
            show_pass:        false,
            algorithm:        Algorithm::XChaCha20Poly1305,
            strength:         DeriveStrength::Moderate,
            job:              JobState::Idle,
        }
    }
}

impl CryptyApp {
    fn add_files(&mut self, new_files: impl IntoIterator<Item = PathBuf>) {
        self.files.extend(new_files);
        self.refresh_mode();
    }

    fn refresh_mode(&mut self) {
        match detect_mode(&self.files) {
            Some(m) => { self.mode = m; self.mixed_files = false; }
            None    => {                self.mixed_files = true;  }
        }
    }

    fn clear_files(&mut self) {
        self.files.clear();
        self.mode = Mode::Encrypt;
        self.mixed_files = false;
    }
}

impl eframe::App for CryptyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {

        // ── Drag & drop ──────────────────────────────────────────────
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw.dropped_files.iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            self.add_files(dropped);
        }

        // ── Mise à jour progression depuis le thread ─────────────────
        if let JobState::Running { progress, receiver } = &self.job {
            while let Ok(pct) = receiver.try_recv() {
                *progress.lock().unwrap() = pct;
            }
            ctx.request_repaint();
            if *progress.lock().unwrap() >= 100 {
                self.job = JobState::Done(Ok("Traitement terminé".to_string()));
            }
        }

        // Bloquer l'interface principale si la modale est ouverte
        let main_ui_enabled = self.modal_state == ModalState::None;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(main_ui_enabled, |ui| {
                ui.heading("🔐 Cryptyrust");
                ui.separator();

                let is_running = matches!(self.job, JobState::Running { .. });

                // ── Indicateur de mode ────────────────────────────────────
                ui.horizontal(|ui| {
                    if self.mixed_files {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            "⚠  Fichiers hétérogènes : certains sont chiffrés, d'autres non",
                        );
                    } else if self.files.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "— En attente de fichiers —");
                    } else {
                        match self.mode {
                            Mode::Encrypt => ui.colored_label(
                                egui::Color32::from_rgb(100, 180, 255),
                                "🔒  Mode détecté : Chiffrement",
                            ),
                            Mode::Decrypt => ui.colored_label(
                                egui::Color32::from_rgb(100, 220, 130),
                                "🔓  Mode détecté : Déchiffrement",
                            ),
                        };
                    }
                });

                ui.add_space(8.0);

                // ── Zone drop ────────────────────────────────────────────
                let available_width = ui.available_width();
                let zone_height = 80.0f32.max(20.0 * self.files.len() as f32 + 20.0);
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(available_width, zone_height),
                    egui::Sense::click(),
                );

                let border_color = if self.mixed_files {
                    egui::Color32::from_rgb(200, 160, 0)
                } else {
                    egui::Color32::from_rgb(80, 80, 80)
                };

                ui.painter().rect_filled(rect, 6.0, egui::Color32::from_rgb(30, 30, 30));
                ui.painter().rect_stroke(rect, 6.0,
                                         egui::Stroke::new(1.0, border_color),
                                         egui::StrokeKind::Outside);

                if self.files.is_empty() {
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER,
                                      "📂  Glissez des fichiers ici ou cliquez pour choisir",
                                      egui::FontId::proportional(14.0), egui::Color32::GRAY);
                } else {
                    let mut y = rect.top() + 10.0;
                    for f in &self.files {
                        let icon = if is_cryptyrust_file(f) { "🔒 " } else { "📄 " };
                        let name = format!("{}{}", icon,
                                           f.file_name().unwrap_or_default().to_string_lossy());
                        ui.painter().text(
                            egui::pos2(rect.center().x, y),
                            egui::Align2::CENTER_TOP,
                            name,
                            egui::FontId::proportional(13.0),
                            egui::Color32::WHITE,
                        );
                        y += 20.0;
                    }
                }

                if response.hovered() && !is_running {
                    ui.painter().rect_stroke(rect, 6.0,
                                             egui::Stroke::new(2.0, egui::Color32::from_rgb(100, 150, 255)),
                                             egui::StrokeKind::Outside);
                }

                if response.clicked() && !is_running {
                    if let Some(paths) = rfd::FileDialog::new().pick_files() {
                        self.add_files(paths);
                    }
                }

                if !self.files.is_empty() && !is_running {
                    if ui.small_button("🗑  Effacer la liste").clicked() {
                        self.clear_files();
                    }
                }

                ui.add_space(8.0);

                // ── Options chiffrement ──────────────────────────────────
                if self.mode == Mode::Encrypt && !self.mixed_files && !is_running {
                    ui.horizontal(|ui| {
                        ui.label("Algorithme :");
                        egui::ComboBox::from_id_salt("algo")
                            .selected_text(format!("{}", self.algorithm))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.algorithm,
                                                    Algorithm::XChaCha20Poly1305, "XChacha20Poly1305");
                                ui.selectable_value(&mut self.algorithm,
                                                    Algorithm::Aes256Gcm, "AES-256-GCM");
                                ui.selectable_value(&mut self.algorithm,
                                                    Algorithm::Aes256GcmSiv, "AES-256-GCM-SIV");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Sécurité Argon2 :");
                        egui::ComboBox::from_id_salt("strength")
                            .selected_text(format!("{:?}", self.strength))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.strength,
                                                    DeriveStrength::Interactive, "Interactive (rapide)");
                                ui.selectable_value(&mut self.strength,
                                                    DeriveStrength::Moderate, "Moderate");
                                ui.selectable_value(&mut self.strength,
                                                    DeriveStrength::Sensitive, "Sensitive (lent)");
                            });
                    });
                }

                ui.add_space(12.0);

                // ── Barre de progression / bouton d'action ────────────────
                match &self.job {
                    JobState::Running { progress, .. } => {
                        let pct = *progress.lock().unwrap();
                        ui.label(format!("Traitement en cours... {}%", pct));
                        ui.add(egui::ProgressBar::new(pct as f32 / 100.0)
                            .show_percentage()
                            .animate(true));
                    }
                    JobState::Done(Ok(msg)) => {
                        ui.colored_label(egui::Color32::GREEN, format!("✅ {}", msg));
                        if ui.button("Nouveau traitement").clicked() {
                            self.job = JobState::Idle;
                        }
                    }
                    JobState::Done(Err(msg)) => {
                        ui.colored_label(egui::Color32::RED, format!("❌ {}", msg));
                        if ui.button("Réessayer").clicked() {
                            self.job = JobState::Idle;
                        }
                    }
                    JobState::Idle => {
                        // Le mot de passe sera demandé plus tard, on vérifie juste les fichiers
                        let can_run = !self.files.is_empty() && !self.mixed_files;

                        let label = match self.mode {
                            Mode::Encrypt => "🔒 Chiffrer",
                            Mode::Decrypt => "🔓 Déchiffrer",
                        };

                        if ui.add_enabled(can_run, egui::Button::new(label)
                            .min_size(egui::vec2(120.0, 32.0))).clicked()
                        {
                            // On prépare et on ouvre la modale
                            self.password_input.clear();
                            self.password_confirm.clear();
                            self.password_error = None;
                            self.show_pass = false;
                            
                            self.modal_state = match self.mode {
                                Mode::Encrypt => ModalState::Encrypt,
                                Mode::Decrypt => ModalState::Decrypt,
                            };
                        }

                        if self.mixed_files {
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                "Retirez les fichiers hétérogènes avant de continuer.",
                            );
                        }
                    }
                }
            });
        });

        // ── Fenêtre modale pour le mot de passe ───────────────────────
        let mut start_processing = false;
        let mut close_modal = false;

        if self.modal_state != ModalState::None {
            let title = match self.modal_state {
                ModalState::Encrypt => "🔒 Définir un mot de passe",
                _                   => "🔓 Entrer le mot de passe",
            };

            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0)) // Centre la fenêtre
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    
                    ui.horizontal(|ui| {
                        ui.label("Mot de passe :");
                        ui.add(egui::TextEdit::singleline(&mut self.password_input)
                            .password(!self.show_pass)
                            .desired_width(200.0));
                        ui.checkbox(&mut self.show_pass, "👁");
                    });

                    // Champ de confirmation uniquement pour le chiffrement
                    if self.modal_state == ModalState::Encrypt {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label("Confirmer    :");
                            ui.add(egui::TextEdit::singleline(&mut self.password_confirm)
                                .password(!self.show_pass)
                                .desired_width(200.0));
                        });
                    }

                    if let Some(err) = &self.password_error {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::RED, err);
                    }

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.button("Valider").clicked() {
                            if self.password_input.is_empty() {
                                self.password_error = Some("Le mot de passe ne peut pas être vide.".into());
                            } else if self.modal_state == ModalState::Encrypt && self.password_input != self.password_confirm {
                                self.password_error = Some("Les mots de passe ne correspondent pas.".into());
                            } else {
                                start_processing = true;
                                close_modal = true;
                            }
                        }
                        if ui.button("Annuler").clicked() {
                            close_modal = true;
                        }
                    });
                });
        }

        if close_modal {
            self.modal_state = ModalState::None;
        }

        if start_processing {
            // On clone le mot de passe validé pour le passer au thread
            let valid_password = self.password_input.clone();
            self.start_job(ctx.clone(), valid_password);
        }
    }
}

impl CryptyApp {
    fn start_job(&mut self, ctx: egui::Context, password: String) { // <--- Ajout de l'argument password
        let files    = self.files.clone();
        let mode     = self.mode;
        let algo     = self.algorithm;
        let strength = self.strength;

        let (tx, rx) = mpsc::channel::<i32>();
        let progress = Arc::new(Mutex::new(0i32));
        let progress_clone = progress.clone();

        self.job = JobState::Running { progress, receiver: rx };
        self.clear_files();

        std::thread::spawn(move || {
            let total = files.len();
            let mut errors: Vec<String> = vec![];
            let mut ok_count = 0usize;

            for (i, path) in files.iter().enumerate() {
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

                let tx_clone = tx.clone();
                let file_index = i;
                let total_files = total;

                let sender = {
                    let tx = tx_clone;
                    struct ScaledProgress {
                        tx:    Sender<i32>,
                        base:  i32,
                        scale: i32,
                    }
                    impl Ui for ScaledProgress {
                        fn output(&self, pct: i32) {
                            let global = self.base + pct * self.scale / 100;
                            let _ = self.tx.send(global);
                        }
                    }
                    ScaledProgress {
                        tx,
                        base:  (file_index * 100 / total_files) as i32,
                        scale: (100 / total_files) as i32,
                    }
                };

                let mut config = Config::new(
                    if mode == Mode::Encrypt { Direction::Encrypt } else { Direction::Decrypt },
                    algo,
                    strength,
                    Secret::new(password.clone()), // <--- Utilisation du mot de passe passé en paramètre
                    Some(in_file),
                    Some(out_file),
                    Box::new(sender),
                    HashMode::NoHash,
                    BenchMode::WriteToFilesystem,
                );

                match main_routine(&mut config) {
                    Ok(_)  => ok_count += 1,
                    Err(e) => errors.push(format!(
                        "{}: {:?}",
                        path.file_name().unwrap_or_default().to_string_lossy(), e
                    )),
                }
            }

            let _ = tx.send(100);
            *progress_clone.lock().unwrap() = 100;
            ctx.request_repaint();

            let _ = (ok_count, errors);
        });
    }
}
