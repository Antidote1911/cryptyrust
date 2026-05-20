use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::app::CryptyApp;
use crate::file_utils::{get_file_size, read_encryption_info, algo_label, derive_label, is_cryptyrust_file, Mode};
use cryptyrust_core::{Algorithm, DeriveStrength};

pub fn render_config_menu(app: &mut CryptyApp, ui: &mut egui::Ui, is_running: bool) {
    ui.menu_button("Config", |ui| {
        ui.add_enabled_ui(!is_running, |ui| {
            ui.label(egui::RichText::new("Algorithm").strong());
            ui.separator();
            ui.selectable_value(
                &mut app.algorithm,
                Algorithm::XChaCha20Poly1305,
                "XChaCha20Poly1305",
            );
            ui.selectable_value(&mut app.algorithm, Algorithm::Aes256Gcm, "AES-256-GCM");
            ui.selectable_value(
                &mut app.algorithm,
                Algorithm::Aes256GcmSiv,
                "AES-256-GCM-SIV",
            );
            ui.separator();
            ui.label(egui::RichText::new("Argon2 strength").strong());
            ui.separator();
            ui.selectable_value(
                &mut app.strength,
                DeriveStrength::Interactive,
                "Interactive  (fast)",
            );
            ui.selectable_value(&mut app.strength, DeriveStrength::Moderate, "Moderate");
            ui.selectable_value(
                &mut app.strength,
                DeriveStrength::Sensitive,
                "Sensitive  (slow)",
            );
        });
    });
}

pub fn render_password_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let title = match app.mode {
        Mode::Encrypt => "Confirm password",
        Mode::Decrypt => "Password",
    };

    let mut do_ok = false;
    let mut do_cancel = false;

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(310.0, 10.0))
        .show(ctx, |ui| {
            ui.add_space(6.0);

            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.pw)
                    .password(!app.pw_show)
                    .hint_text("Password…")
                    .desired_width(260.0),
            );

            if app.pw_focus {
                resp.request_focus();
                app.pw_focus = false;
            }

            if app.mode == Mode::Encrypt {
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut app.pw_confirm)
                        .password(!app.pw_show)
                        .hint_text("Confirm…")
                        .desired_width(260.0),
                );
            }

            ui.add_space(4.0);
            ui.checkbox(&mut app.pw_show, "Show password");

            if let Some(err) = &app.pw_error {
                ui.add_space(4.0);
                ui.colored_label(egui::Color32::RED, err);
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("  OK  ").clicked() {
                    do_ok = true;
                }
                if ui.button("Cancel").clicked() {
                    do_cancel = true;
                }
            });

            if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                do_ok = true;
            }
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                do_cancel = true;
            }
        });

    if do_ok {
        app.validate_and_start(ctx);
    }
    if do_cancel {
        app.clear_all();
    }
}

pub fn render_about_window(app: &mut CryptyApp, ctx: &egui::Context) {
    let screen_rect = ctx.viewport_rect();
    let overlay_id = egui::Id::new("about_overlay");

    egui::Area::new(overlay_id)
        .fixed_pos(screen_rect.min)
        .show(ctx, |ui| {
            let overlay_rect = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), screen_rect.size());
            ui.scope_builder(egui::UiBuilder::new().max_rect(overlay_rect), |ui| {
                let (rect, response) = ui.allocate_exact_size(overlay_rect.size(), egui::Sense::click());

                ui.painter().rect_filled(
                    rect,
                    0.0,
                    egui::Color32::from_black_alpha(128)
                );

                if response.clicked() {
                    app.show_about = false;
                }
            });
        });

    egui::Window::new("About Cryptyrust")
        .collapsible(false)
        .resizable(false)
        .movable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(350.0, 160.0))
        .show(ctx, |ui| {
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                app.show_about = false;
            }

            ui.add_space(4.0);

            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🔐").size(24.0));
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Cryptyrust")
                                .size(16.0)
                                .strong()
                                .color(egui::Color32::from_rgb(130, 190, 255)),
                        );
                        ui.label(
                            egui::RichText::new("Fast, authenticated file encryption")
                                .size(11.0)
                                .color(egui::Color32::from_gray(170)),
                        );
                    });
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("🔒 Algorithms")
                            .size(12.0)
                            .strong()
                            .color(egui::Color32::from_rgb(100, 200, 130)),
                    );
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new("XChaCha20-Poly1305").size(10.0).color(egui::Color32::from_rgb(200, 220, 255)));
                    ui.label(egui::RichText::new("AES-256-GCM").size(10.0).color(egui::Color32::from_rgb(200, 220, 255)));
                    ui.label(egui::RichText::new("AES-256-GCM-SIV").size(10.0).color(egui::Color32::from_rgb(200, 220, 255)));
                });

                ui.add_space(20.0);

                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("🔑 Key Derivation")
                            .size(12.0)
                            .strong()
                            .color(egui::Color32::from_rgb(100, 200, 130)),
                    );
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new("Argon2id").size(10.0).color(egui::Color32::from_rgb(200, 220, 255)));
                    ui.label(egui::RichText::new("• Interactive, Moderate, Sensitive").size(9.0).color(egui::Color32::from_gray(140)));
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Built with Rust • eframe/egui")
                        .size(9.0)
                        .color(egui::Color32::from_gray(120)),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(egui::RichText::new("Close").size(11.0))
                                .min_size(egui::vec2(50.0, 20.0)),
                        )
                        .clicked()
                    {
                        app.show_about = false;
                    }
                });
            });
        });
}

pub fn render_warning_banner(ui: &mut egui::Ui) {
    let (warn_rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 36.0),
        egui::Sense::hover(),
    );
    ui.painter().rect_filled(warn_rect, 0.0, egui::Color32::from_rgb(80, 60, 0));
    ui.painter().text(
        warn_rect.center(),
        egui::Align2::CENTER_CENTER,
        "⚠  Mixed encrypted / non-encrypted files — remove files below to fix",
        egui::FontId::proportional(12.5),
        egui::Color32::from_rgb(255, 210, 80),
    );
}

fn header_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .small()
            .strong()
            .color(egui::Color32::from_gray(160)),
    );
}

fn render_type_cell(ui: &mut egui::Ui, path: &Path, is_encrypted: bool) {
    let (icon, badge, badge_color) = if is_encrypted {
        ("🔒", "encrypted", egui::Color32::from_rgb(60, 160, 100))
    } else {
        ("📄", "plain", egui::Color32::from_rgb(80, 120, 200))
    };
    let resp = ui.horizontal(|ui| {
        ui.label(egui::RichText::new(icon).size(14.0));
        ui.add_space(4.0);
        ui.label(egui::RichText::new(badge).small().color(badge_color));
    }).response;
    if is_encrypted {
        if let Some((algo, derive)) = read_encryption_info(path) {
            resp.on_hover_text(format!("{} · {}", algo_label(algo), derive_label(derive)));
        }
    }
}

fn render_progress_cell(ui: &mut egui::Ui, pct: i32) {
    let progress_width = ui.available_width().min(110.0);
    let progress_height = 16.0;
    let (progress_rect, _) = ui.allocate_exact_size(
        egui::vec2(progress_width, progress_height),
        egui::Sense::hover(),
    );
    ui.painter().rect_filled(progress_rect, 2.0, egui::Color32::from_rgb(40, 40, 50));
    let fill_width = (progress_width * pct as f32 / 100.0).max(0.0);
    if fill_width > 0.0 {
        let fill_rect = egui::Rect::from_min_size(
            progress_rect.min,
            egui::vec2(fill_width, progress_height),
        );
        let fill_color = if pct >= 100 {
            egui::Color32::from_rgb(40, 160, 80)
        } else {
            egui::Color32::from_rgb(60, 120, 200)
        };
        ui.painter().rect_filled(fill_rect, 2.0, fill_color);
    }
    ui.painter().text(
        progress_rect.center(),
        egui::Align2::CENTER_CENTER,
        format!("{}%", pct),
        egui::FontId::proportional(10.0),
        egui::Color32::WHITE,
    );
}

pub fn render_file_table(ui: &mut egui::Ui, files: &[PathBuf]) -> Option<usize> {
    let mut to_remove: Option<usize> = None;

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(38.0))
        .column(Column::exact(95.0))
        .column(Column::remainder().clip(true))
        .column(Column::initial(200.0).at_least(80.0).clip(true))
        .column(Column::exact(80.0))
        .header(30.0, |mut header| {
            header.col(|ui| { header_label(ui, "Remove"); });
            header.col(|ui| { header_label(ui, "Type"); });
            header.col(|ui| { header_label(ui, "Name"); });
            header.col(|ui| { header_label(ui, "Path"); });
            header.col(|ui| { header_label(ui, "Size"); });
        })
        .body(|mut body| {
            for (i, path) in files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        if ui.add(
                            egui::Button::new(
                                egui::RichText::new("✕")
                                    .size(12.0)
                                    .color(egui::Color32::from_gray(160)),
                            )
                            .min_size(egui::vec2(20.0, 20.0))
                            .fill(egui::Color32::TRANSPARENT),
                        ).clicked() {
                            to_remove = Some(i);
                        }
                    });
                    row.col(|ui| { render_type_cell(ui, path, is_enc); });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(egui::RichText::new(name.as_ref()).color(egui::Color32::WHITE));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(
                            egui::RichText::new(dir)
                                .small()
                                .color(egui::Color32::from_gray(100)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            egui::RichText::new(get_file_size(path))
                                .small()
                                .color(egui::Color32::from_gray(140)),
                        );
                    });
                });
            }
        });

    to_remove
}

pub fn render_processing_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    progress_map: &HashMap<usize, i32>,
    current_idx: usize,
) {
    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(30.0))
        .column(Column::exact(95.0))
        .column(Column::remainder().clip(true))
        .column(Column::initial(200.0).at_least(80.0).clip(true))
        .column(Column::exact(80.0))
        .column(Column::exact(120.0))
        .header(30.0, |mut header| {
            header.col(|_ui| {});
            header.col(|ui| { header_label(ui, "Type"); });
            header.col(|ui| { header_label(ui, "Name"); });
            header.col(|ui| { header_label(ui, "Path"); });
            header.col(|ui| { header_label(ui, "Size"); });
            header.col(|ui| { header_label(ui, "Progress"); });
        })
        .body(|mut body| {
            for (i, path) in files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                let pct = progress_map.get(&i).copied().unwrap_or(0);
                let is_current = i == current_idx;

                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        if is_current && pct < 100 {
                            ui.label(
                                egui::RichText::new("▶")
                                    .size(10.0)
                                    .color(egui::Color32::from_rgb(80, 140, 200)),
                            );
                        }
                    });
                    row.col(|ui| { render_type_cell(ui, path, is_enc); });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        let color = if is_current && pct < 100 {
                            egui::Color32::from_rgb(200, 220, 255)
                        } else {
                            egui::Color32::WHITE
                        };
                        ui.label(egui::RichText::new(name.as_ref()).color(color));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(
                            egui::RichText::new(dir)
                                .small()
                                .color(egui::Color32::from_gray(100)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            egui::RichText::new(get_file_size(path))
                                .small()
                                .color(egui::Color32::from_gray(140)),
                        );
                    });
                    row.col(|ui| { render_progress_cell(ui, pct); });
                });
            }
        });
}

pub fn render_completed_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    statuses: &[crate::job::FileStatus],
) {
    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(38.0))
        .column(Column::exact(95.0))
        .column(Column::remainder().clip(true))
        .column(Column::initial(200.0).at_least(80.0).clip(true))
        .column(Column::exact(80.0))
        .column(Column::initial(200.0).at_least(80.0).clip(true))
        .header(30.0, |mut header| {
            header.col(|ui| { header_label(ui, "Status"); });
            header.col(|ui| { header_label(ui, "Type"); });
            header.col(|ui| { header_label(ui, "Name"); });
            header.col(|ui| { header_label(ui, "Path"); });
            header.col(|ui| { header_label(ui, "Size"); });
            header.col(|ui| { header_label(ui, "Error"); });
        })
        .body(|mut body| {
            for (path, status) in files.iter().zip(statuses.iter()) {
                let is_enc = is_cryptyrust_file(path);
                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        let (icon, color) = match status {
                            crate::job::FileStatus::Success => ("✅", egui::Color32::from_rgb(60, 160, 100)),
                            crate::job::FileStatus::Failed(_) => ("❌", egui::Color32::from_rgb(200, 80, 80)),
                            crate::job::FileStatus::Processing => ("⏳", egui::Color32::from_rgb(200, 160, 80)),
                            crate::job::FileStatus::Pending => ("⏸", egui::Color32::from_gray(120)),
                        };
                        ui.label(egui::RichText::new(icon).size(14.0).color(color));
                    });
                    row.col(|ui| { render_type_cell(ui, path, is_enc); });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(egui::RichText::new(name.as_ref()).color(egui::Color32::WHITE));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(
                            egui::RichText::new(dir)
                                .small()
                                .color(egui::Color32::from_gray(100)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            egui::RichText::new(get_file_size(path))
                                .small()
                                .color(egui::Color32::from_gray(140)),
                        );
                    });
                    row.col(|ui| {
                        if let crate::job::FileStatus::Failed(error) = status {
                            ui.label(
                                egui::RichText::new(error)
                                    .small()
                                    .color(egui::Color32::from_rgb(255, 150, 150)),
                            );
                        }
                    });
                });
            }
        });
}
