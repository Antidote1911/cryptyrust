use eframe::egui;

use crate::app::CryptyApp;
use crate::file_utils::{arsenic_strength_label, cipher_short_label, is_cryptyrust_file, Mode};
use crate::job::JobState;
use crate::ui::components;

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
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            components::render_config_menu(app, ui, is_running);

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
                ui.label(egui::RichText::new("🔒").size(13.0).weak());
                ui.label(egui::RichText::new("Arsenic V2"));
                ui.separator();
                ui.label(egui::RichText::new("🔑").size(13.0).weak());
                ui.label(egui::RichText::new(format!(
                    "Argon2id · {}",
                    arsenic_strength_label(app.arsenic_strength)
                )));
                ui.separator();
                ui.label(
                    egui::RichText::new(format!(
                        "Hdr: {}  ·  Pld: {}",
                        cipher_short_label(app.hdr_cipher),
                        cipher_short_label(app.pld_cipher),
                    ))
                    .size(12.0)
                    .weak(),
                );
            });
        });
}

pub fn render_action_bar(
    app: &mut CryptyApp,
    ui: &mut egui::Ui,
    is_running: bool,
    popup_open: bool,
) {
    let can_act = !app.files.is_empty() && !app.mixed && !is_running && !popup_open;

    let can_change_pw =
        app.files.len() == 1 && is_cryptyrust_file(&app.files[0]) && !is_running && !popup_open;

    let mut do_open_popup = false;
    let mut do_change_pw = false;
    let mut do_clear = false;
    let mut do_add = false;

    egui::Panel::bottom("actionbar")
        .exact_size(52.0)
        .show_inside(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal_centered(|ui| {
                let btn_label = if app.mixed {
                    "⚠  Mixed files"
                } else {
                    match app.mode {
                        Mode::Encrypt => "🔒  Encrypt",
                        Mode::Decrypt => "🔓  Decrypt",
                    }
                };

                let btn = egui::Button::new(egui::RichText::new(btn_label).size(15.0).strong())
                    .min_size(egui::vec2(150.0, 32.0));

                if ui.add_enabled(can_act, btn).clicked() {
                    do_open_popup = true;
                }

                ui.add_space(12.0);

                if ui
                    .add_enabled(
                        can_change_pw,
                        egui::Button::new("🔑  Change password").min_size(egui::vec2(140.0, 32.0)),
                    )
                    .clicked()
                {
                    do_change_pw = true;
                }

                ui.add_space(12.0);

                if ui
                    .add_enabled(
                        !is_running && !popup_open,
                        egui::Button::new("➕  Add files").min_size(egui::vec2(100.0, 32.0)),
                    )
                    .clicked()
                {
                    do_add = true;
                }

                ui.add_space(12.0);

                if ui
                    .add_enabled(
                        !is_running && !popup_open,
                        egui::Button::new("🗑  Clear").min_size(egui::vec2(80.0, 32.0)),
                    )
                    .clicked()
                {
                    do_clear = true;
                }
            });
        });

    if do_open_popup {
        app.open_popup();
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
}

pub fn render_central_panel(app: &mut CryptyApp, ui: &mut egui::Ui) {
    egui::CentralPanel::default().show_inside(ui, |ui| {
        let avail = ui.available_rect_before_wrap();
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());

        match &app.job {
            JobState::Running {
                progress,
                current_file,
                processing_files,
                ..
            } => {
                render_processing_view(ui, progress, current_file, processing_files);
            }
            JobState::Completed { files, statuses } => {
                render_completed_view(ui, files, statuses);
            }
            JobState::Idle => {
                if app.files.is_empty() {
                    render_drop_zone(ui, avail, hovering, app);
                } else {
                    render_file_list(ui, avail, hovering, app);
                }
            }
        }
    });
}

fn render_processing_view(
    ui: &mut egui::Ui,
    progress: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<usize, i32>>>,
    current_file: &std::sync::Arc<std::sync::Mutex<usize>>,
    processing_files: &[std::path::PathBuf],
) {
    let current_idx = *current_file.lock().unwrap();
    let file_progress = progress.lock().unwrap();
    components::render_processing_table(ui, processing_files, &file_progress, current_idx);
}

fn render_completed_view(
    ui: &mut egui::Ui,
    files: &[std::path::PathBuf],
    statuses: &[crate::job::FileStatus],
) {
    components::render_completed_table(ui, files, statuses);
}

fn render_drop_zone(ui: &mut egui::Ui, avail: egui::Rect, hovering: bool, app: &mut CryptyApp) {
    if hovering {
        ui.painter().rect_stroke(
            avail,
            4.0,
            egui::Stroke::new(2.0, ui.visuals().selection.stroke.color),
            egui::StrokeKind::Inside,
        );
    }

    ui.painter().text(
        avail.center() - egui::vec2(0.0, 14.0),
        egui::Align2::CENTER_CENTER,
        "Drop files here to encrypt or decrypt",
        egui::FontId::proportional(18.0),
        ui.visuals().text_color(),
    );
    ui.painter().text(
        avail.center() + egui::vec2(0.0, 14.0),
        egui::Align2::CENTER_CENTER,
        "or click to browse",
        egui::FontId::proportional(14.0),
        ui.visuals().weak_text_color(),
    );

    if ui
        .interact(avail, ui.id().with("idle_click"), egui::Sense::click())
        .clicked()
    {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            app.add_files(paths);
        }
    }
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
