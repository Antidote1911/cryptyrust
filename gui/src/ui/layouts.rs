use eframe::egui;

use crate::app::CryptyApp;
use crate::file_utils::{algo_label, is_cryptyrust_file, Mode};
use crate::job::JobState;
use crate::ui::components;

pub fn render_menu_bar(
    app: &mut CryptyApp,
    ui: &mut egui::Ui,
    is_running: bool,
    popup_open: bool,
) {
    egui::Panel::top("menubar").show_inside(ui, |ui| {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui
                    .add_enabled(
                        !is_running && !popup_open,
                        egui::Button::new("Add files…"),
                    )
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
        });
    });
}

pub fn render_bottom_bar(app: &CryptyApp, ui: &mut egui::Ui) {
    egui::Panel::bottom("bottombar")
        .exact_size(30.0)
        .show_inside(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(
                    egui::RichText::new("🔒")
                        .size(13.0)
                        .color(egui::Color32::from_gray(150)),
                );
                ui.label(
                    egui::RichText::new(algo_label(app.algorithm))
                        .small()
                        .color(egui::Color32::from_gray(200)),
                );
                ui.separator();
                ui.label(
                    egui::RichText::new("🔑")
                        .size(13.0)
                        .color(egui::Color32::from_gray(150)),
                );
                ui.label(
                    egui::RichText::new(format!("Argon2id · {:?}", app.strength))
                        .small()
                        .color(egui::Color32::from_gray(200)),
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

    let mut do_open_popup = false;
    let mut do_clear = false;
    let mut do_add = false;

    egui::Panel::bottom("actionbar")
        .exact_size(52.0)
        .show_inside(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal_centered(|ui| {
                let (btn_label, btn_color) = if app.mixed {
                    ("⚠  Mixed files", egui::Color32::from_rgb(120, 90, 0))
                } else {
                    match app.mode {
                        Mode::Encrypt => ("🔒  Encrypt", egui::Color32::from_rgb(40, 120, 200)),
                        Mode::Decrypt => ("🔓  Decrypt", egui::Color32::from_rgb(40, 160, 80)),
                    }
                };

                let btn = egui::Button::new(egui::RichText::new(btn_label).size(15.0).strong())
                    .min_size(egui::vec2(150.0, 32.0))
                    .fill(btn_color);

                if ui.add_enabled(can_act, btn).clicked() {
                    do_open_popup = true;
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
                        egui::Button::new("🗑  Clear")
                            .min_size(egui::vec2(80.0, 32.0))
                            .fill(egui::Color32::from_rgb(100, 35, 35)),
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
                render_processing_view(ui, avail, progress, current_file, processing_files);
            }
            JobState::Completed { files, statuses } => {
                render_completed_view(ui, avail, files, statuses);
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
    avail: egui::Rect,
    progress: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<usize, i32>>>,
    current_file: &std::sync::Arc<std::sync::Mutex<usize>>,
    processing_files: &[std::path::PathBuf],
) {
    let current_idx = *current_file.lock().unwrap();
    let file_progress = progress.lock().unwrap();

    ui.painter()
        .rect_filled(avail, 0.0, egui::Color32::from_rgb(18, 18, 24));

    components::render_file_list_header(ui, avail, true);

    egui::ScrollArea::vertical()
        .id_salt("running_file_list")
        .show(ui, |ui| {
            ui.set_min_width(avail.width());

            for (i, path) in processing_files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                let is_current = i == current_idx;
                let file_pct = file_progress.get(&i).copied().unwrap_or(0);

                components::render_file_row(
                    ui, i, path, is_enc, true, is_current, Some(file_pct),
                );
            }
        });
}

fn render_completed_view(
    ui: &mut egui::Ui,
    avail: egui::Rect,
    files: &[std::path::PathBuf],
    statuses: &[crate::job::FileStatus],
) {
    ui.painter()
        .rect_filled(avail, 0.0, egui::Color32::from_rgb(18, 18, 24));

    components::render_completed_file_list_header(ui, avail);

    egui::ScrollArea::vertical()
        .id_salt("completed_file_list")
        .show(ui, |ui| {
            ui.set_min_width(avail.width());

            for (i, (path, status)) in files.iter().zip(statuses.iter()).enumerate() {
                let is_enc = is_cryptyrust_file(path);
                components::render_completed_file_row(ui, i, path, is_enc, status);
            }
        });
}

fn render_drop_zone(
    ui: &mut egui::Ui,
    avail: egui::Rect,
    hovering: bool,
    app: &mut CryptyApp,
) {
    let bg_color = if hovering {
        egui::Color32::from_rgb(40, 65, 110)
    } else {
        egui::Color32::from_rgb(25, 45, 75)
    };

    {
        let painter = ui.painter();
        painter.rect_filled(avail, 0.0, bg_color);
        if hovering {
            painter.rect_stroke(
                avail,
                0.0,
                egui::Stroke::new(3.0, egui::Color32::from_rgb(100, 160, 255)),
                egui::StrokeKind::Inside,
            );
        }
        painter.text(
            avail.center() - egui::vec2(0.0, 14.0),
            egui::Align2::CENTER_CENTER,
            "Drop files here to encrypt or decrypt",
            egui::FontId::proportional(18.0),
            egui::Color32::from_gray(210),
        );
        painter.text(
            avail.center() + egui::vec2(0.0, 14.0),
            egui::Align2::CENTER_CENTER,
            "or click to browse",
            egui::FontId::proportional(14.0),
            egui::Color32::from_gray(140),
        );
    }

    if ui
        .interact(avail, ui.id().with("idle_click"), egui::Sense::click())
        .clicked()
    {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            app.add_files(paths);
        }
    }
}

fn render_file_list(
    ui: &mut egui::Ui,
    avail: egui::Rect,
    hovering: bool,
    app: &mut CryptyApp,
) {
    let top_offset = if app.mixed { 36.0 } else { 0.0 };

    ui.painter()
        .rect_filled(avail, 0.0, egui::Color32::from_rgb(18, 18, 24));

    if app.mixed {
        components::render_warning_banner(ui, avail);
    }

    components::render_file_list_header(ui, avail.translate(egui::vec2(0.0, top_offset)), false);

    let list_rect = egui::Rect::from_min_size(
        avail.min + egui::vec2(0.0, top_offset + 30.0),
        egui::vec2(avail.width(), avail.height() - top_offset - 30.0),
    );

    ui.scope_builder(egui::UiBuilder::new().max_rect(list_rect), |ui| {
        let file_data: Vec<(std::path::PathBuf, bool)> = app
            .files
            .iter()
            .map(|p| (p.clone(), is_cryptyrust_file(p)))
            .collect();

        let mut to_remove: Option<usize> = None;

        egui::ScrollArea::vertical()
            .id_salt("file_list")
            .show(ui, |ui| {
                ui.set_min_width(list_rect.width());

                for (i, (path, is_enc)) in file_data.iter().enumerate() {
                    if components::render_file_row(ui, i, path, *is_enc, false, false, None) {
                        to_remove = Some(i);
                    }
                }
            });

        if let Some(idx) = to_remove {
            app.remove_file(idx);
        }
    });

    if hovering {
        ui.painter().rect_stroke(
            avail,
            0.0,
            egui::Stroke::new(3.0, egui::Color32::from_rgb(100, 160, 255)),
            egui::StrokeKind::Inside,
        );
    }
}