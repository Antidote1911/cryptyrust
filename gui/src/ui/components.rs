use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::app::CryptyApp;
use crate::file_utils::{
    algo_label, derive_label, get_file_size, is_cryptyrust_file, read_encryption_info, Mode,
};
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
            ui.separator();
            ui.checkbox(&mut app.pem_output, "PEM output (text)");
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
                ui.colored_label(ui.visuals().error_fg_color, err);
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
                let (rect, response) =
                    ui.allocate_exact_size(overlay_rect.size(), egui::Sense::click());

                ui.painter()
                    .rect_filled(rect, 0.0, egui::Color32::from_black_alpha(128));

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
        .fixed_size(egui::vec2(380.0, 200.0))
        .show(ctx, |ui| {
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                app.show_about = false;
            }

            ui.add_space(8.0);

            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🔐").size(32.0));
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Cryptyrust").size(22.0).strong());
                        ui.label(
                            egui::RichText::new(format!(
                                "v{}  —  by Antidote1911",
                                env!("CARGO_PKG_VERSION")
                            ))
                            .size(13.0)
                            .weak(),
                        );
                        ui.label(
                            egui::RichText::new("Fast, authenticated file encryption")
                                .size(13.0)
                                .weak(),
                        );
                    });
                });
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Algorithms").size(13.0).strong());
                    ui.add_space(3.0);
                    ui.label(egui::RichText::new("XChaCha20-Poly1305").size(13.0));
                    ui.label(egui::RichText::new("AES-256-GCM").size(13.0));
                    ui.label(egui::RichText::new("AES-256-GCM-SIV").size(13.0));
                });

                ui.add_space(24.0);

                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Key Derivation").size(13.0).strong());
                    ui.add_space(3.0);
                    ui.label(egui::RichText::new("Argon2id").size(13.0));
                    ui.label(
                        egui::RichText::new("Interactive · Moderate · Sensitive")
                            .size(12.0)
                            .weak(),
                    );
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Built with Rust • eframe/egui").weak());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new("Close").min_size(egui::vec2(50.0, 20.0)))
                        .clicked()
                    {
                        app.show_about = false;
                    }
                });
            });
        });
}

pub fn render_warning_banner(ui: &mut egui::Ui) {
    let (warn_rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::hover());
    ui.painter().text(
        warn_rect.center(),
        egui::Align2::CENTER_CENTER,
        "⚠  Mixed encrypted / non-encrypted files — remove files below to fix",
        egui::FontId::proportional(12.5),
        ui.visuals().warn_fg_color,
    );
}

fn header_label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).small().strong());
}

fn render_type_cell(ui: &mut egui::Ui, path: &Path, is_encrypted: bool) {
    let (icon, badge) = if is_encrypted {
        ("🔒", "encrypted")
    } else {
        ("📄", "plain")
    };
    let resp = ui
        .horizontal(|ui| {
            ui.label(egui::RichText::new(icon).size(14.0));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(badge));
        })
        .response;
    if is_encrypted {
        if let Some((algo, derive)) = read_encryption_info(path) {
            resp.on_hover_text(format!("{} · {}", algo_label(algo), derive_label(derive)));
        }
    }
}

fn render_progress_cell(ui: &mut egui::Ui, pct: i32) {
    let fraction = (pct as f32 / 100.0).clamp(0.0, 1.0);
    ui.add(
        egui::ProgressBar::new(fraction)
            .text(format!("{}%", pct))
            .desired_width(110.0),
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
            header.col(|ui| {
                header_label(ui, "Remove");
            });
            header.col(|ui| {
                header_label(ui, "Type");
            });
            header.col(|ui| {
                header_label(ui, "Name");
            });
            header.col(|ui| {
                header_label(ui, "Path");
            });
            header.col(|ui| {
                header_label(ui, "Size");
            });
        })
        .body(|mut body| {
            for (i, path) in files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("✕").size(12.0))
                                    .min_size(egui::vec2(20.0, 20.0))
                                    .fill(egui::Color32::TRANSPARENT),
                            )
                            .clicked()
                        {
                            to_remove = Some(i);
                        }
                    });
                    row.col(|ui| {
                        render_type_cell(ui, path, is_enc);
                    });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(egui::RichText::new(name.as_ref()));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(egui::RichText::new(dir).weak());
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(get_file_size(path)).weak());
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
            header.col(|ui| {
                header_label(ui, "Type");
            });
            header.col(|ui| {
                header_label(ui, "Name");
            });
            header.col(|ui| {
                header_label(ui, "Path");
            });
            header.col(|ui| {
                header_label(ui, "Size");
            });
            header.col(|ui| {
                header_label(ui, "Progress");
            });
        })
        .body(|mut body| {
            for (i, path) in files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                let pct = progress_map.get(&i).copied().unwrap_or(0);
                let is_current = i == current_idx;

                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        if is_current && pct < 100 {
                            ui.label(egui::RichText::new("▶").size(10.0));
                        }
                    });
                    row.col(|ui| {
                        render_type_cell(ui, path, is_enc);
                    });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(egui::RichText::new(name.as_ref()));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(egui::RichText::new(dir).weak());
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(get_file_size(path)).weak());
                    });
                    row.col(|ui| {
                        render_progress_cell(ui, pct);
                    });
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
            header.col(|ui| {
                header_label(ui, "Status");
            });
            header.col(|ui| {
                header_label(ui, "Type");
            });
            header.col(|ui| {
                header_label(ui, "Name");
            });
            header.col(|ui| {
                header_label(ui, "Path");
            });
            header.col(|ui| {
                header_label(ui, "Size");
            });
            header.col(|ui| {
                header_label(ui, "Error");
            });
        })
        .body(|mut body| {
            for (path, status) in files.iter().zip(statuses.iter()) {
                let is_enc = is_cryptyrust_file(path);
                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        let icon = match status {
                            crate::job::FileStatus::Success => "✅",
                            crate::job::FileStatus::Failed(_) => "❌",
                            crate::job::FileStatus::Processing => "⏳",
                            crate::job::FileStatus::Pending => "⏸",
                        };
                        ui.label(egui::RichText::new(icon).size(14.0));
                    });
                    row.col(|ui| {
                        render_type_cell(ui, path, is_enc);
                    });
                    row.col(|ui| {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(egui::RichText::new(name.as_ref()));
                    });
                    row.col(|ui| {
                        let dir = path.parent().and_then(|p| p.to_str()).unwrap_or("");
                        ui.label(egui::RichText::new(dir).weak());
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(get_file_size(path)).weak());
                    });
                    row.col(|ui| {
                        if let crate::job::FileStatus::Failed(error) = status {
                            ui.label(egui::RichText::new(error).color(ui.visuals().error_fg_color));
                        }
                    });
                });
            }
        });
}
