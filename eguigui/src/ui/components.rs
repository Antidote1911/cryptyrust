use eframe::egui;
use std::path::Path;

use crate::app::CryptyApp;
use crate::file_utils::{get_file_size, Mode};
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
    // Créer un overlay semi-transparent pour bloquer l'arrière-plan
    let screen_rect = ctx.screen_rect();
    let overlay_id = egui::Id::new("about_overlay");

    egui::Area::new(overlay_id)
        .fixed_pos(screen_rect.min)
        .show(ctx, |ui| {
            // Overlay semi-transparent qui couvre tout l'écran
            let overlay_rect = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), screen_rect.size());
            ui.allocate_ui_at_rect(overlay_rect, |ui| {
                let (rect, response) = ui.allocate_exact_size(overlay_rect.size(), egui::Sense::click());

                // Fond semi-transparent
                ui.painter().rect_filled(
                    rect,
                    0.0,
                    egui::Color32::from_black_alpha(128)
                );

                // Fermer en cliquant sur l'overlay
                if response.clicked() {
                    app.show_about = false;
                }
            });
        });

    // Fenêtre About par-dessus l'overlay
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

            // Header
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

            // Content in two columns
            ui.horizontal(|ui| {
                // Left column - Algorithms
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

                // Right column - Key Derivation
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

            // Footer
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


pub fn render_warning_banner(ui: &mut egui::Ui, avail: egui::Rect) {
    let warn_rect = egui::Rect::from_min_size(avail.min, egui::vec2(avail.width(), 36.0));
    ui.painter()
        .rect_filled(warn_rect, 0.0, egui::Color32::from_rgb(80, 60, 0));
    ui.painter().text(
        warn_rect.center(),
        egui::Align2::CENTER_CENTER,
        "⚠  Mixed encrypted / non-encrypted files — remove files below to fix",
        egui::FontId::proportional(12.5),
        egui::Color32::from_rgb(255, 210, 80),
    );
}

pub fn render_file_list_header(ui: &mut egui::Ui, avail: egui::Rect, show_progress: bool) {
    let header_rect = egui::Rect::from_min_size(avail.min, egui::vec2(avail.width(), 30.0));
    ui.painter()
        .rect_filled(header_rect, 0.0, egui::Color32::from_rgb(30, 30, 40));

    ui.allocate_ui_at_rect(header_rect, |ui| {
        ui.horizontal_centered(|ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Remove")
                    .small()
                    .strong()
                    .color(egui::Color32::from_gray(160)),
            );
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("Name")
                    .small()
                    .strong()
                    .color(egui::Color32::from_gray(160)),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if show_progress {
                    ui.label(
                        egui::RichText::new("Progress")
                            .small()
                            .strong()
                            .color(egui::Color32::from_gray(160)),
                    );
                    ui.add_space(120.0);
                }
                ui.label(
                    egui::RichText::new("Size")
                        .small()
                        .strong()
                        .color(egui::Color32::from_gray(160)),
                );
                ui.add_space(80.0);
                ui.label(
                    egui::RichText::new("Path")
                        .small()
                        .strong()
                        .color(egui::Color32::from_gray(160)),
                );
            });
        });
    });
}

pub fn render_completed_file_list_header(ui: &mut egui::Ui, avail: egui::Rect) {
    let header_rect = egui::Rect::from_min_size(avail.min, egui::vec2(avail.width(), 30.0));
    ui.painter()
        .rect_filled(header_rect, 0.0, egui::Color32::from_rgb(30, 30, 40));

    ui.allocate_ui_at_rect(header_rect, |ui| {
        ui.horizontal_centered(|ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Status")
                    .small()
                    .strong()
                    .color(egui::Color32::from_gray(160)),
            );
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("Name")
                    .small()
                    .strong()
                    .color(egui::Color32::from_gray(160)),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Error")
                        .small()
                        .strong()
                        .color(egui::Color32::from_gray(160)),
                );
                ui.add_space(120.0);
                ui.label(
                    egui::RichText::new("Size")
                        .small()
                        .strong()
                        .color(egui::Color32::from_gray(160)),
                );
                ui.add_space(80.0);
                ui.label(
                    egui::RichText::new("Path")
                        .small()
                        .strong()
                        .color(egui::Color32::from_gray(160)),
                );
            });
        });
    });
}

pub fn render_file_row(
    ui: &mut egui::Ui,
    index: usize,
    path: &Path,
    is_encrypted: bool,
    disabled: bool,
    is_current: bool,
    progress: Option<i32>,
) -> bool {
    let mut should_remove = false;

    let row_bg = if index % 2 == 0 {
        egui::Color32::from_rgb(22, 22, 30)
    } else {
        egui::Color32::from_rgb(28, 28, 38)
    };

    let (row_rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 32.0), egui::Sense::hover());

    ui.painter().rect_filled(row_rect, 0.0, row_bg);

    if is_current && progress.map_or(false, |p| p < 100) {
        ui.painter().rect_stroke(
            row_rect,
            0.0,
            egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 140, 200)),
            egui::StrokeKind::Inside,
        );
    }

    ui.allocate_ui_at_rect(row_rect, |ui| {
        ui.horizontal_centered(|ui| {
            ui.add_space(8.0);

            // Remove button
            if ui
                .add_enabled(
                    !disabled,
                    egui::Button::new(
                        egui::RichText::new("✕")
                            .size(12.0)
                            .color(if disabled {
                                egui::Color32::from_gray(100)
                            } else {
                                egui::Color32::from_gray(160)
                            }),
                    )
                    .min_size(egui::vec2(20.0, 20.0))
                    .fill(egui::Color32::TRANSPARENT),
                )
                .clicked()
            {
                should_remove = true;
            }

            ui.add_space(8.0);

            // Icon and badge
            let (icon, badge_color) = if is_encrypted {
                ("🔒", egui::Color32::from_rgb(60, 160, 100))
            } else {
                ("📄", egui::Color32::from_rgb(80, 120, 200))
            };
            ui.label(egui::RichText::new(icon).size(14.0));
            ui.add_space(4.0);

            let badge = if is_encrypted { "encrypted" } else { "plain" };
            ui.label(egui::RichText::new(badge).small().color(badge_color));
            ui.add_space(8.0);

            // File name
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            ui.label(egui::RichText::new(&name).color(egui::Color32::WHITE));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);

                // Progress bar (if provided)
                if let Some(file_pct) = progress {
                    let progress_width = 100.0;
                    let progress_height = 16.0;
                    let (progress_rect, _) = ui.allocate_exact_size(
                        egui::vec2(progress_width, progress_height),
                        egui::Sense::hover(),
                    );

                    // Progress bar background
                    ui.painter().rect_filled(
                        progress_rect,
                        2.0,
                        egui::Color32::from_rgb(40, 40, 50),
                    );

                    // Progress bar fill
                    let fill_width = (progress_width * file_pct as f32 / 100.0).max(0.0);
                    if fill_width > 0.0 {
                        let fill_rect = egui::Rect::from_min_size(
                            progress_rect.min,
                            egui::vec2(fill_width, progress_height),
                        );
                        let fill_color = if file_pct >= 100 {
                            egui::Color32::from_rgb(40, 160, 80)
                        } else {
                            egui::Color32::from_rgb(60, 120, 200)
                        };
                        ui.painter().rect_filled(fill_rect, 2.0, fill_color);
                    }

                    // Progress percentage text
                    ui.painter().text(
                        progress_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        format!("{}%", file_pct),
                        egui::FontId::proportional(10.0),
                        egui::Color32::WHITE,
                    );

                    ui.add_space(12.0);
                }

                // File size
                let size_text = get_file_size(path);
                ui.label(
                    egui::RichText::new(size_text)
                        .small()
                        .color(egui::Color32::from_gray(140)),
                );

                ui.add_space(12.0);

                // File path
                let dir = path
                    .parent()
                    .and_then(|p| p.to_str())
                    .unwrap_or("")
                    .to_string();
                ui.label(
                    egui::RichText::new(dir)
                        .small()
                        .color(egui::Color32::from_gray(100)),
                );
            });
        });
    });

    should_remove
}

pub fn render_completed_file_row(
    ui: &mut egui::Ui,
    index: usize,
    path: &std::path::Path,
    is_encrypted: bool,
    status: &crate::job::FileStatus,
) {
    use crate::file_utils::get_file_size;

    let row_bg = if index % 2 == 0 {
        egui::Color32::from_rgb(22, 22, 30)
    } else {
        egui::Color32::from_rgb(28, 28, 38)
    };

    let (row_rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 32.0), egui::Sense::hover());

    ui.painter().rect_filled(row_rect, 0.0, row_bg);

    ui.allocate_ui_at_rect(row_rect, |ui| {
        ui.horizontal_centered(|ui| {
            ui.add_space(8.0);

            // Status icon
            let (status_icon, status_color) = match status {
                crate::job::FileStatus::Success => ("✅", egui::Color32::from_rgb(60, 160, 100)),
                crate::job::FileStatus::Failed(_) => ("❌", egui::Color32::from_rgb(200, 80, 80)),
                crate::job::FileStatus::Processing(_) => ("⏳", egui::Color32::from_rgb(200, 160, 80)),
                crate::job::FileStatus::Pending => ("⏸", egui::Color32::from_gray(120)),
            };

            ui.label(egui::RichText::new(status_icon).size(14.0).color(status_color));
            ui.add_space(8.0);

            // File icon and badge
            let (icon, badge_color) = if is_encrypted {
                ("🔒", egui::Color32::from_rgb(60, 160, 100))
            } else {
                ("📄", egui::Color32::from_rgb(80, 120, 200))
            };
            ui.label(egui::RichText::new(icon).size(14.0));
            ui.add_space(4.0);

            let badge = if is_encrypted { "encrypted" } else { "plain" };
            ui.label(egui::RichText::new(badge).small().color(badge_color));
            ui.add_space(8.0);

            // File name
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            ui.label(egui::RichText::new(&name).color(egui::Color32::WHITE));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);

                // Error message (if any)
                if let crate::job::FileStatus::Failed(error) = status {
                    ui.label(
                        egui::RichText::new(error)
                            .small()
                            .color(egui::Color32::from_rgb(255, 150, 150)),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("")
                            .small(),
                    );
                }

                ui.add_space(12.0);

                // File size
                let size_text = get_file_size(path);
                ui.label(
                    egui::RichText::new(size_text)
                        .small()
                        .color(egui::Color32::from_gray(140)),
                );

                ui.add_space(12.0);

                // File path
                let dir = path
                    .parent()
                    .and_then(|p| p.to_str())
                    .unwrap_or("")
                    .to_string();
                ui.label(
                    egui::RichText::new(dir)
                        .small()
                        .color(egui::Color32::from_gray(100)),
                );
            });
        });
    });
}