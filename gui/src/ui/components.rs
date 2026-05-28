use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::app::CryptyApp;
use crate::file_utils::{
    arsenic_strength_label, cipher_label, cipher_short_label, get_file_size, is_cryptyrust_file,
    Mode,
};
use crate::job::PasswordPopup;
use cryptyrust_core::{best_combination, ArsenicStrength, CipherId, Compression};

pub fn render_config_menu(app: &mut CryptyApp, ui: &mut egui::Ui, is_running: bool) {
    ui.menu_button("Config", |ui| {
        ui.add_enabled_ui(!is_running, |ui| {
            // ── KDF strength ──────────────────────────────────────────
            ui.label(egui::RichText::new("Argon2id strength").strong());
            ui.separator();
            ui.selectable_value(
                &mut app.arsenic_strength,
                ArsenicStrength::Interactive,
                arsenic_strength_label(ArsenicStrength::Interactive),
            );
            ui.selectable_value(
                &mut app.arsenic_strength,
                ArsenicStrength::Sensitive,
                arsenic_strength_label(ArsenicStrength::Sensitive),
            );

            ui.add_space(6.0);

            // ── Header cipher ─────────────────────────────────────────
            ui.label(egui::RichText::new("Header cipher").strong());
            ui.label(
                egui::RichText::new("envelope — encryption only")
                    .small()
                    .weak(),
            );
            ui.separator();
            for cipher in [
                CipherId::DeoxysII256,
                CipherId::Aes256GcmSiv,
                CipherId::XChaCha20Poly1305,
            ] {
                ui.selectable_value(&mut app.hdr_cipher, cipher, cipher_label(cipher));
            }

            ui.add_space(6.0);

            // ── Payload cipher ────────────────────────────────────────
            ui.label(egui::RichText::new("Payload cipher").strong());
            ui.label(
                egui::RichText::new("blocks — encryption only")
                    .small()
                    .weak(),
            );
            ui.separator();
            for cipher in [
                CipherId::DeoxysII256,
                CipherId::Aes256GcmSiv,
                CipherId::XChaCha20Poly1305,
            ] {
                ui.selectable_value(&mut app.pld_cipher, cipher, cipher_label(cipher));
            }

            ui.add_space(6.0);

            // ── Compression ───────────────────────────────────────────
            ui.label(egui::RichText::new("Compression").strong());
            ui.label(
                egui::RichText::new("before encryption — disabled by default")
                    .small()
                    .weak(),
            );
            ui.separator();
            ui.checkbox(&mut app.compress, "zstd  (level 3)");

            ui.add_space(6.0);
            ui.separator();

            if ui
                .add_enabled(
                    !is_running && !app.bench_running,
                    egui::Button::new("⏱  Benchmark ciphers…"),
                )
                .on_hover_text("Find the fastest cipher for this machine")
                .clicked()
            {
                let ctx = ui.ctx().clone();
                ui.close();
                app.start_bench(ctx);
            }
        });
    });
}

/// Benchmark results window — call every frame when `app.show_bench` is true.
pub fn render_bench_window(app: &mut CryptyApp, ctx: &egui::Context) {
    if !app.show_bench {
        return;
    }

    let mut close = false;
    let mut apply: Option<(CipherId, CipherId)> = None;

    egui::Window::new("Cipher Benchmark")
        .collapsible(false)
        .resizable(false)
        .min_width(360.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            if app.bench_running {
                ui.label("Benchmarking ciphers on 32 MiB of data…");
                ui.add_space(6.0);
                ui.label(if app.bench_progress < 15 {
                    "Running Interactive Argon2id key derivation…"
                } else {
                    "Testing AEAD cipher throughput…"
                });
                ui.add_space(4.0);
                ui.add(
                    egui::ProgressBar::new(app.bench_progress as f32 / 100.0)
                        .show_percentage()
                        .animate(true),
                );
            } else if let Some(results) = &app.bench_results {
                ui.label("Results (32 MiB payload, Interactive Argon2id key)");
                ui.add_space(8.0);

                egui::Grid::new("bench_grid")
                    .num_columns(3)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Cipher").strong());
                        ui.label(egui::RichText::new("Encrypt").strong());
                        ui.label(egui::RichText::new("Decrypt").strong());
                        ui.end_row();

                        for (i, r) in results.iter().enumerate() {
                            let name = cipher_label(r.cipher);
                            if i == 0 {
                                ui.label(
                                    egui::RichText::new(format!("★  {name}"))
                                        .color(egui::Color32::from_rgb(40, 200, 100)),
                                );
                            } else {
                                ui.label(name);
                            }
                            ui.label(format!("{:.0} MiB/s", r.encrypt_mibps));
                            ui.label(format!("{:.0} MiB/s", r.decrypt_mibps));
                            ui.end_row();
                        }
                    });

                ui.add_space(8.0);

                let (best_hdr, best_pld) = best_combination(results);
                ui.label(format!(
                    "Fastest: {} for header and payload",
                    cipher_label(best_hdr)
                ));

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Apply fastest combination").clicked() {
                        apply = Some((best_hdr, best_pld));
                    }
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
            }
        });

    if let Some((h, p)) = apply {
        app.hdr_cipher = h;
        app.pld_cipher = p;
        app.show_bench = false;
    }
    if close {
        app.show_bench = false;
    }
}

pub fn compression_short_label(c: Compression) -> &'static str {
    match c {
        Compression::None => "no compression",
        Compression::Zstd(_) => "zstd",
    }
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

pub fn render_change_pw_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let mut do_ok = false;
    let mut do_cancel = false;

    egui::Window::new("Change password")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(310.0, 10.0))
        .show(ctx, |ui| {
            ui.add_space(6.0);

            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.cpw_old)
                    .password(!app.cpw_show)
                    .hint_text("Current password…")
                    .desired_width(260.0),
            );
            if app.cpw_focus {
                resp.request_focus();
                app.cpw_focus = false;
            }

            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.cpw_new)
                    .password(!app.cpw_show)
                    .hint_text("New password…")
                    .desired_width(260.0),
            );

            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.cpw_confirm)
                    .password(!app.cpw_show)
                    .hint_text("Confirm new password…")
                    .desired_width(260.0),
            );

            ui.add_space(4.0);
            ui.checkbox(&mut app.cpw_show, "Show passwords");

            if let Some(err) = &app.cpw_error {
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
        app.validate_and_change_pw(ctx);
    }
    if do_cancel {
        app.popup = PasswordPopup::Closed;
    }
}

pub fn render_about_window(app: &mut CryptyApp, ctx: &egui::Context) {
    let modal =
        egui::Modal::new(egui::Id::new("about_modal")).backdrop_color(egui::Color32::TRANSPARENT);

    let response = modal.show(ctx, |ui| {
        ui.set_min_width(380.0);

        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            app.show_about = false;
        }

        ui.add_space(8.0);

        ui.vertical_centered(|ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!(
                        "../../../packaging/cryptyrust-icon.png"
                    ))
                    .fit_to_exact_size(egui::vec2(120.0, 120.0))
                    .corner_radius(12.0),
                );
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
                ui.label(egui::RichText::new("Arsenic V1 format").size(13.0).strong());
                ui.add_space(3.0);
                ui.label(
                    egui::RichText::new(format!("{} (header)", cipher_short_label(app.hdr_cipher)))
                        .size(13.0),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "{} (payload)",
                        cipher_short_label(app.pld_cipher)
                    ))
                    .size(13.0),
                );
                ui.label(egui::RichText::new("BLAKE3 Merkle tree integrity").size(13.0));
            });

            ui.add_space(24.0);

            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Key Derivation").size(13.0).strong());
                ui.add_space(3.0);
                ui.label(egui::RichText::new("Argon2id").size(13.0));
                ui.label(
                    egui::RichText::new("Interactive · Sensitive")
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

    if response.should_close() {
        app.show_about = false;
    }
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

fn render_type_cell(ui: &mut egui::Ui, is_encrypted: bool) {
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
        resp.on_hover_text("Arsenic V1 format");
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
                        render_type_cell(ui, is_enc);
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
                        render_type_cell(ui, is_enc);
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
                        render_type_cell(ui, is_enc);
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
