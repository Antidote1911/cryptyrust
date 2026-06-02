use eframe::egui;

use crate::app::CryptyApp;
use crate::file_utils::{arsenic_strength_label, cipher_short_label, is_cryptyrust_file, Mode};
use crate::job::JobState;
use crate::ui::components;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub fn render_menu_bar(app: &mut CryptyApp, ui: &mut egui::Ui, is_running: bool, popup_open: bool) {
    egui::Panel::top("menubar").show_inside(ui, |ui| {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui
                    .add_enabled(!is_running && !popup_open, egui::Button::new("Add files…"))
                    .clicked()
                {
                    ui.close();
                    if let Some(paths) = rfd::FileDialog::new().pick_files() {
                        app.add_files(paths);
                    }
                }
                if ui
                    .add_enabled(!is_running && !popup_open, egui::Button::new("Add folder…"))
                    .on_hover_text("Add all files inside a folder (recursive)")
                    .clicked()
                {
                    ui.close();
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        app.add_files(std::iter::once(folder));
                    }
                }
                ui.separator();
                if ui
                    .add_enabled(
                        !app.files.is_empty() && !is_running && !popup_open,
                        egui::Button::new("Clear list"),
                    )
                    .clicked()
                {
                    ui.close();
                    app.clear_all();
                }
                if is_running {
                    ui.separator();
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("⏹  Stop all tasks")
                                    .color(egui::Color32::from_rgb(220, 80, 60)),
                            ),
                        )
                        .on_hover_text("Cancel all pending and in-progress operations")
                        .clicked()
                    {
                        ui.close();
                        app.job.cancel_all();
                    }
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            components::render_config_menu(app, ui, is_running);

            ui.menu_button("Keys", |ui| {
                if ui.button("Key Manager…").clicked() {
                    ui.close();
                    app.show_key_manager = true;
                }
            });

            ui.menu_button("About", |ui| {
                if ui.button("About Cryptyrust…").clicked() {
                    ui.close();
                    app.show_about = true;
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let icon = if app.dark_mode { "☀" } else { "🌙" };
                if ui.add(egui::Button::new(icon).frame(false)).clicked() {
                    app.dark_mode = !app.dark_mode;
                }
            });
        });
    });
}

pub fn render_bottom_bar(app: &CryptyApp, ui: &mut egui::Ui) {
    egui::Panel::bottom("bottombar")
        .exact_size(30.0)
        .show_inside(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(egui::RichText::new("🔑").size(13.0).weak());
                ui.label(egui::RichText::new(format!(
                    "Argon2  ·  {}",
                    arsenic_strength_label(app.arsenic_strength)
                )));
                ui.separator();
                ui.label(egui::RichText::new(format!(
                    "Hdr: {}  ·  Pld: {}",
                    cipher_short_label(app.hdr_cipher),
                    cipher_short_label(app.pld_cipher),
                )));
            });
        });
}

pub fn render_action_bar(
    app: &mut CryptyApp,
    ui: &mut egui::Ui,
    is_running: bool,
    popup_open: bool,
) {
    let completed = matches!(app.job, JobState::Completed { .. });

    let can_act = !app.files.is_empty() && !app.mixed && !is_running && !popup_open;

    let can_change_pw =
        app.files.len() == 1 && is_cryptyrust_file(&app.files[0]) && !is_running && !popup_open;

    let mut do_open_popup = false;
    let mut do_change_pw = false;
    let mut do_clear = false;
    let mut do_add = false;
    let mut do_add_folder = false;
    let mut do_quit = false;

    egui::Panel::bottom("actionbar")
        .exact_size(52.0)
        .show_inside(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal_centered(|ui| {
                if completed {
                    // ── Post-opération : Clear uniquement ──────────────
                    if ui
                        .add(egui::Button::new("🗑  Clear").min_size(egui::vec2(80.0, 32.0)))
                        .clicked()
                    {
                        do_clear = true;
                    }
                } else {
                    // ── Add files ──────────────────────────────────────
                    if ui
                        .add_enabled(
                            !is_running && !popup_open,
                            egui::Button::new("➕  Add files").min_size(egui::vec2(100.0, 32.0)),
                        )
                        .clicked()
                    {
                        do_add = true;
                    }

                    ui.add_space(4.0);

                    // ── Add folder ─────────────────────────────────────
                    if ui
                        .add_enabled(
                            !is_running && !popup_open,
                            egui::Button::new("📁  Add folder").min_size(egui::vec2(105.0, 32.0)),
                        )
                        .on_hover_text("Add all files inside a folder (recursive)")
                        .clicked()
                    {
                        do_add_folder = true;
                    }

                    if !app.files.is_empty() {
                        ui.add_space(8.0);

                        // ── Clear ──────────────────────────────────────
                        if ui
                            .add_enabled(
                                !is_running && !popup_open,
                                egui::Button::new("🗑  Clear").min_size(egui::vec2(80.0, 32.0)),
                            )
                            .clicked()
                        {
                            do_clear = true;
                        }

                        ui.add_space(8.0);

                        // ── Change password ────────────────────────────
                        if ui
                            .add_enabled(
                                can_change_pw,
                                egui::Button::new("🔑  Change password")
                                    .min_size(egui::vec2(140.0, 32.0)),
                            )
                            .clicked()
                        {
                            do_change_pw = true;
                        }

                        ui.add_space(8.0);

                        // ── Encrypt / Decrypt ──────────────────────────
                        let btn_label = if app.mixed {
                            "⚠  Mixed files"
                        } else {
                            match app.mode {
                                Mode::Encrypt => "🔒  Encrypt",
                                Mode::Decrypt => "🔓  Decrypt",
                            }
                        };

                        let btn =
                            egui::Button::new(egui::RichText::new(btn_label).size(15.0).strong())
                                .min_size(egui::vec2(150.0, 32.0));

                        if ui.add_enabled(can_act, btn).clicked() {
                            do_open_popup = true;
                        }
                    }
                }

                // ── Quit (far right) ───────────────────────────────────
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new("✕  Quit").min_size(egui::vec2(80.0, 32.0)))
                        .clicked()
                    {
                        do_quit = true;
                    }
                });
            });
        });

    if do_open_popup {
        app.open_popup_or_auto_decrypt(ui.ctx());
    }
    if do_change_pw {
        app.open_change_pw_popup();
    }
    if do_clear {
        app.clear_all();
    }
    if do_add {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            app.add_files(paths);
        }
    }
    if do_add_folder {
        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
            app.add_files(std::iter::once(folder));
        }
    }
    if do_quit {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

pub fn render_central_panel(app: &mut CryptyApp, ui: &mut egui::Ui) {
    let mut completed_remove: Option<usize> = None;

    egui::CentralPanel::default().show_inside(ui, |ui| {
        let avail = ui.available_rect_before_wrap();
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());

        match &app.job {
            JobState::Running {
                progress,
                current_file,
                processing_files,
                cancel_flags,
                cancel_all,
                ..
            } => {
                render_processing_view(
                    ui,
                    progress,
                    current_file,
                    processing_files,
                    cancel_flags,
                    cancel_all,
                );
            }
            JobState::Completed {
                files,
                statuses,
                success_label,
            } => {
                completed_remove = render_completed_view(ui, files, statuses, success_label);
                // Sender identity banner — offer to add as contact
                let sender_banner = app.pending_contact_from_file.as_ref().map(|p| p.name.clone());
                if let Some(sender_name) = sender_banner {
                    ui.add_space(4.0);
                    let color = egui::Color32::from_rgb(80, 160, 220);
                    let mut do_add = false;
                    let mut do_dismiss = false;
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("📨 De : {sender_name}  — ajouter aux contacts ?"))
                                .color(color),
                        );
                        if ui.button("Ajouter").clicked() { do_add = true; }
                        if ui.button("✕").clicked()       { do_dismiss = true; }
                    });
                    if do_add     { app.confirm_add_contact_from_file(); }
                    if do_dismiss { app.pending_contact_from_file = None; }
                }
            }
            JobState::Idle => {
                if app.files.is_empty() {
                    render_drop_zone(ui, avail, hovering);
                } else {
                    render_file_list(ui, avail, hovering, app);
                }
            }
        }
    });

    if let Some(idx) = completed_remove {
        if let JobState::Completed { files, statuses, .. } = &mut app.job {
            files.remove(idx);
            statuses.remove(idx);
            if files.is_empty() {
                app.clear_all();
            }
        }
    }
}

fn render_processing_view(
    ui: &mut egui::Ui,
    progress: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<usize, i32>>>,
    current_file: &std::sync::Arc<std::sync::Mutex<usize>>,
    processing_files: &[std::path::PathBuf],
    cancel_flags: &[Arc<AtomicBool>],
    cancel_all: &Arc<AtomicBool>,
) {
    let current_idx = *current_file.lock().unwrap();
    let file_progress = progress.lock().unwrap();
    components::render_processing_table(
        ui,
        processing_files,
        &file_progress,
        current_idx,
        cancel_flags,
        cancel_all,
    );
}

fn render_completed_view(
    ui: &mut egui::Ui,
    files: &[std::path::PathBuf],
    statuses: &[crate::job::FileStatus],
    success_label: &str,
) -> Option<usize> {
    components::render_completed_table(ui, files, statuses, success_label)
}

fn render_drop_zone(ui: &mut egui::Ui, avail: egui::Rect, hovering: bool) {
    if hovering {
        ui.painter().rect_stroke(
            avail,
            4.0,
            egui::Stroke::new(2.0, ui.visuals().selection.stroke.color),
            egui::StrokeKind::Inside,
        );
    }

    ui.painter().text(
        avail.center(),
        egui::Align2::CENTER_CENTER,
        "Drop files here to encrypt or decrypt",
        egui::FontId::proportional(18.0),
        ui.visuals().text_color(),
    );
}

fn render_file_list(ui: &mut egui::Ui, avail: egui::Rect, hovering: bool, app: &mut CryptyApp) {
    if app.mixed {
        components::render_warning_banner(ui);
    }

    if let Some(idx) = components::render_file_table(ui, &app.files) {
        app.remove_file(idx);
    }

    if hovering {
        ui.painter().rect_stroke(
            avail,
            0.0,
            egui::Stroke::new(2.0, ui.visuals().selection.stroke.color),
            egui::StrokeKind::Inside,
        );
    }
}
