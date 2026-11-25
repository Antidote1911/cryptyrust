// egui layout code is one long declarative block per window; splitting it by
// line count would only scatter the layout.
#![allow(clippy::too_many_lines)]

use crate::i18n::{tr, trf, Lang};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::app::{ConfigCategory, CryptyApp};
use crate::file_utils::{
    arsenic_strength_label, cipher_label, cipher_short_label, FileMeta, Mode,
};
use crate::job::{FileStatus, PasswordPopup};
use arsenic::encode_pubkey;
use crate::keystore::{pubkey_short, serialize_identity};
use arsenic::{best_combination, ArsenicStrength, CipherId, KemLevel};

/// "Config" menu: only opens the settings window and the benchmark.
pub fn render_config_menu(app: &mut CryptyApp, ui: &mut egui::Ui, is_running: bool) {
    ui.menu_button("Config", |ui| {
        if ui.button(tr("Settings…")).clicked() {
            ui.close();
            app.show_config = true;
        }
        if ui
            .add_enabled(
                !is_running && !app.bench_running,
                egui::Button::new(tr("⏱  Benchmark ciphers…")),
            )
            .on_hover_text(tr("Find the fastest cipher for this machine"))
            .clicked()
        {
            let ctx = ui.ctx().clone();
            ui.close();
            app.start_bench(ctx);
        }
    });
}

/// Labelled combo box row of a settings grid: `label | combo`, then end of row.
fn combo_row<T: PartialEq + Copy>(
    ui: &mut egui::Ui,
    label: &str,
    hint: &str,
    value: &mut T,
    options: &[(T, &str)],
) {
    let resp = ui.label(label);
    if !hint.is_empty() {
        resp.on_hover_text(hint);
    }
    let selected = options
        .iter()
        .find(|(v, _)| v == value)
        .map_or("", |(_, text)| *text);
    egui::ComboBox::from_id_salt(label)
        .width(COMBO_WIDTH)
        .selected_text(selected)
        .show_ui(ui, |ui| {
            for (v, text) in options {
                ui.selectable_value(value, *v, *text);
            }
        });
    ui.end_row();
}

const COMBO_WIDTH: f32 = 250.0;

fn settings_grid(ui: &mut egui::Ui, id: &str, add_rows: impl FnOnce(&mut egui::Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([16.0, 10.0])
        .show(ui, add_rows);
}

fn settings_note(ui: &mut egui::Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(egui::RichText::new(text).small().weak());
}

/// Renders the settings inside the container the caller provides (the
/// settings viewport): categories on the left, the selected page on the right.
/// Changes apply immediately and are saved on exit.
///
/// Sets `*close = true` when the user clicks Close or presses Escape.
pub fn render_config_content(
    app: &mut CryptyApp,
    ui: &mut egui::Ui,
    is_running: bool,
    close: &mut bool,
) {
    egui::Panel::bottom("config_buttons")
        .exact_size(40.0)
        .show_inside(ui, |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(tr("Close")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    *close = true;
                }
                if is_running {
                    ui.label(
                        egui::RichText::new(tr("Encryption settings are locked while a job is running."))
                            .small()
                            .color(egui::Color32::from_rgb(220, 150, 40)),
                    );
                }
            });
        });

    egui::Panel::left("config_categories")
        .exact_size(130.0)
        .resizable(false)
        .show_inside(ui, |ui| {
            ui.add_space(6.0);
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                for category in ConfigCategory::ALL {
                    ui.selectable_value(&mut app.config_category, category, category.label());
                }
            });
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.add_space(6.0);
        ui.heading(app.config_category.label());
        ui.separator();
        ui.add_space(6.0);
        egui::ScrollArea::vertical().show(ui, |ui| match app.config_category {
            ConfigCategory::General => render_config_general(app, ui),
            ConfigCategory::Encryption => {
                ui.add_enabled_ui(!is_running, |ui| render_config_encryption(app, ui));
            }
            ConfigCategory::Output => {
                ui.add_enabled_ui(!is_running, |ui| render_config_output(app, ui));
            }
        });
    });
}

fn render_config_general(app: &mut CryptyApp, ui: &mut egui::Ui) {
    let mut language = app.language;
    settings_grid(ui, "config_general", |ui| {
        combo_row(
            ui,
            tr("Language"),
            "",
            &mut language,
            &Lang::ALL.map(|l| (l, l.name())),
        );
        combo_row(
            ui,
            tr("Theme"),
            "",
            &mut app.dark_mode,
            &[(false, tr("Light")), (true, tr("Dark"))],
        );
    });
    if language != app.language {
        app.set_language(language);
    }
}

fn render_config_encryption(app: &mut CryptyApp, ui: &mut egui::Ui) {
    let ciphers = [
        CipherId::DeoxysII256,
        CipherId::Aes256GcmSiv,
        CipherId::XChaCha20Poly1305,
    ]
    .map(|c| (c, cipher_label(c)));

    settings_grid(ui, "config_encryption", |ui| {
        combo_row(
            ui,
            tr("Argon2id strength"),
            tr("Memory cost of the password key derivation."),
            &mut app.arsenic_strength,
            &[ArsenicStrength::Interactive, ArsenicStrength::Sensitive]
                .map(|s| (s, arsenic_strength_label(s))),
        );
        combo_row(
            ui,
            tr("Header cipher"),
            tr("Protects the envelope (keyslots and metadata)."),
            &mut app.hdr_cipher,
            &ciphers,
        );
        combo_row(
            ui,
            tr("Payload cipher"),
            tr("Protects the data blocks."),
            &mut app.pld_cipher,
            &ciphers,
        );
        combo_row(
            ui,
            tr("ML-KEM level"),
            tr("Post-quantum level of the asymmetric keyslots."),
            &mut app.kem_level,
            &[
                (KemLevel::L768, tr("ML-KEM-768  (NIST level 3)")),
                (KemLevel::L1024, tr("ML-KEM-1024  (NIST level 5)")),
            ],
        );
    });
    settings_note(
        ui,
        tr("Used when encrypting. Decryption reads these from the file."),
    );
}

fn render_config_output(app: &mut CryptyApp, ui: &mut egui::Ui) {
    settings_grid(ui, "config_output", |ui| {
        let mut enabled = app.compress.is_some();
        let was_enabled = enabled;
        combo_row(
            ui,
            "Compression",
            tr("Compress the data before encrypting it."),
            &mut enabled,
            &[(false, tr("Disabled")), (true, "zstd")],
        );
        if enabled != was_enabled {
            app.compress = enabled.then_some(3);
        }
        if let Some(ref mut level) = app.compress {
            ui.label(tr("Compression level"))
                .on_hover_text(tr("1 = fastest, 22 = smallest output"));
            ui.add(egui::Slider::new(level, 1..=22));
            ui.end_row();
        }
        combo_row(
            ui,
            "Format",
            tr("ASCII armor is base64 text with BEGIN/END headers,\nsafe for email and text channels."),
            &mut app.armor,
            &[(false, tr("Binary (.arsn)")), (true, tr("ASCII armor (.arsn.armor)"))],
        );
    });
    if app.compress.is_some() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                tr("⚠ Compression leaks plaintext entropy via ciphertext size.\nDisable for size-sensitive data."),
            )
            .small()
            .color(egui::Color32::from_rgb(220, 150, 40)),
        );
    }
    settings_note(ui, tr("Used when encrypting."));
}

/// Benchmark results window — call every frame when `app.show_bench` is true.
pub fn render_bench_window(app: &mut CryptyApp, ctx: &egui::Context) {
    if !app.show_bench {
        return;
    }

    let mut close = false;
    let mut apply: Option<(CipherId, CipherId)> = None;

    egui::Window::new(tr("Cipher Benchmark"))
        .collapsible(false)
        .resizable(false)
        .min_width(360.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            if app.bench_running {
                ui.label(tr("Benchmarking ciphers on 32 MiB of data…"));
                ui.add_space(6.0);
                ui.label(if app.bench_progress < 15 {
                    tr("Running Interactive Argon2id key derivation…")
                } else {
                    tr("Testing AEAD cipher throughput…")
                });
                ui.add_space(4.0);
                ui.add(
                    egui::ProgressBar::new(pct_fraction(app.bench_progress))
                        .show_percentage()
                        .animate(true),
                );
                ui.add_space(8.0);
                if app.bench_cancel.load(Ordering::Relaxed) {
                    ui.label(
                        egui::RichText::new(tr("Cancelling…"))
                            .color(egui::Color32::from_rgb(220, 160, 40)),
                    );
                } else if ui
                    .button(
                        egui::RichText::new(tr("⏹  Stop"))
                            .color(egui::Color32::from_rgb(220, 80, 60)),
                    )
                    .clicked()
                {
                    app.stop_bench();
                }
            } else if let Some(results) = &app.bench_results {
                ui.label(tr("Results (32 MiB payload, Interactive Argon2id key)"));
                ui.add_space(8.0);

                egui::Grid::new("bench_grid")
                    .num_columns(3)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(tr("Cipher")).strong());
                        ui.label(egui::RichText::new(tr("Encrypt")).strong());
                        ui.label(egui::RichText::new(tr("Decrypt")).strong());
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
                ui.label(trf(
                    tr("Fastest: {cipher} for header and payload"),
                    &[("cipher", &cipher_label(best_hdr))],
                ));

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(tr("Apply fastest combination")).clicked() {
                        apply = Some((best_hdr, best_pld));
                    }
                    if ui.button(tr("Close")).clicked() {
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

pub fn render_password_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let title = match app.mode {
        Mode::Encrypt => tr("Encrypt"),
        Mode::Decrypt => tr("Decrypt"),
    };

    let has_contacts = app.mode == Mode::Encrypt
        && (!app.contacts.is_empty() || !app.keys.is_empty());
    let has_decrypt_keys = app.mode == Mode::Decrypt && !app.keys.is_empty();
    let window_width = if has_contacts || has_decrypt_keys { 360.0f32 } else { 310.0 };

    let mut do_ok = false;
    let mut do_cancel = false;

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .min_width(window_width)
        .max_width(window_width)
        .show(ctx, |ui| {
            ui.add_space(6.0);

            // ── Password fields ───────────────────────────────────────────
            let n_sel_now = app.pw_selected_own_keys.iter().filter(|&&s| s).count()
                + app.pw_selected_recipients.iter().filter(|&&s| s).count();
            let pw_optional = (app.mode == Mode::Encrypt && n_sel_now > 0)
                || (app.mode == Mode::Decrypt && app.decrypt_key_index.is_some());

            let pw_hint = if pw_optional && app.mode == Mode::Encrypt {
                tr("Password… (optional — recipients selected)")
            } else if app.mode == Mode::Encrypt {
                tr("Password… (minimum 8 characters)")
            } else if pw_optional && app.mode == Mode::Decrypt {
                tr("Password… (optional — keypair selected)")
            } else {
                tr("Password…")
            };

            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.pw)
                    .password(!app.pw_show)
                    .hint_text(pw_hint)
                    .desired_width(window_width - 24.0),
            );
            if app.pw_focus {
                resp.request_focus();
                app.pw_focus = false;
            }

            // Confirm field: shown in encrypt mode only when a password is being set.
            if app.mode == Mode::Encrypt && !app.pw.is_empty() {
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut app.pw_confirm)
                        .password(!app.pw_show)
                        .hint_text(tr("Confirm password…"))
                        .desired_width(window_width - 24.0),
                );
            } else {
                // Clear confirm so it doesn't cause a mismatch when the user
                // leaves the password empty and submits.
                app.pw_confirm.clear();
            }

            ui.add_space(4.0);
            if !app.pw.is_empty() {
                ui.checkbox(&mut app.pw_show, tr("Show password"));
            }

            // Note when encrypting without a password.
            if pw_optional && app.pw.is_empty() {
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        tr("ℹ No password — only selected recipients can decrypt."),
                    )
                    .small()
                    .color(egui::Color32::from_rgb(80, 160, 220)),
                );
            }

            // ── Recipient selection (encrypt mode, when any key/contact exists) ──
            if has_contacts {
                // Keep selection vecs in sync with their lists.
                if app.pw_selected_own_keys.len() != app.keys.len() {
                    app.pw_selected_own_keys.resize(app.keys.len(), false);
                }
                if app.pw_selected_recipients.len() != app.contacts.len() {
                    app.pw_selected_recipients.resize(app.contacts.len(), false);
                }

                let n_sel = app.pw_selected_own_keys.iter().filter(|&&s| s).count()
                    + app.pw_selected_recipients.iter().filter(|&&s| s).count();

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(tr("Recipients")).strong());
                    if n_sel > 0 {
                        ui.label(
                            egui::RichText::new(trf("({n_sel} selected)", &[("n_sel", &n_sel)]))
                                .small()
                                .color(egui::Color32::from_rgb(80, 180, 80)),
                        );
                    } else {
                        ui.label(egui::RichText::new(tr("(none — password only)")).small().weak());
                    }
                });
                ui.label(
                    egui::RichText::new(
                        tr("Checked keys can decrypt without the password."),
                    )
                    .small()
                    .weak(),
                );
                ui.add_space(4.0);

                let n_rows = app.keys.len() + app.contacts.len();
                let scroll_h = list_height(n_rows, 24.0, 24.0, 180.0);
                egui::ScrollArea::vertical()
                    .max_height(scroll_h)
                    .id_salt("pw_recipients")
                    .show(ui, |ui| {
                        // ── My keypairs ───────────────────────────────────
                        if !app.keys.is_empty() {
                            ui.label(
                                egui::RichText::new(tr("My keypairs"))
                                    .small()
                                    .strong()
                                    .weak(),
                            );
                            for i in 0..app.keys.len() {
                                let short = pubkey_short(&app.keys[i].public_key);
                                let label = format!("{}   {}", app.keys[i].name, short);
                                ui.checkbox(&mut app.pw_selected_own_keys[i], label);
                            }
                        }
                        // ── Contacts ──────────────────────────────────────
                        // Exclude contacts whose key is already one of the user's own keypairs.
                        let visible_contacts: Vec<usize> = (0..app.contacts.len())
                            .filter(|&i| {
                                let pk = app.contacts[i].public_key;
                                !app.keys.iter().any(|k| k.public_key == pk)
                            })
                            .collect();
                        if !visible_contacts.is_empty() {
                            if !app.keys.is_empty() {
                                ui.add_space(4.0);
                            }
                            ui.label(
                                egui::RichText::new("Contacts")
                                    .small()
                                    .strong()
                                    .weak(),
                            );
                            for i in visible_contacts {
                                let short = pubkey_short(&app.contacts[i].public_key);
                                let label =
                                    format!("{}   {}", app.contacts[i].name, short);
                                ui.checkbox(&mut app.pw_selected_recipients[i], label);
                            }
                        }
                    });
            }

            // ── Keypair selection (decrypt mode) ──────────────────────────
            if has_decrypt_keys {
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(tr("Decrypt with keypair")).strong());
                    if app.decrypt_key_index.is_none() {
                        ui.label(egui::RichText::new(tr("(none — use password)")).small().weak());
                    }
                });
                ui.label(
                    egui::RichText::new(tr("Select your keypair if the file was encrypted for you."))
                        .small()
                        .weak(),
                );
                ui.add_space(4.0);

                let scroll_h = list_height(app.keys.len(), 26.0, 8.0, 150.0);
                egui::ScrollArea::vertical()
                    .max_height(scroll_h)
                    .id_salt("decrypt_key_sel")
                    .show(ui, |ui| {
                        // "None" option: password only
                        ui.radio_value(
                            &mut app.decrypt_key_index,
                            None,
                            egui::RichText::new(tr("None (password only)")).weak(),
                        );
                        for i in 0..app.keys.len() {
                            let short = pubkey_short(&app.keys[i].public_key);
                            let label = format!("{}   {}", app.keys[i].name, short);
                            ui.radio_value(&mut app.decrypt_key_index, Some(i), label);
                        }
                    });
            }

            // ── Error + buttons ───────────────────────────────────────────
            if let Some(err) = &app.pw_error {
                ui.add_space(4.0);
                ui.colored_label(ui.visuals().error_fg_color, err);
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("  OK  ").clicked() {
                    do_ok = true;
                }
                if ui.button(tr("Cancel")).clicked() {
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
        app.close_popup();
    }
}

pub fn render_change_pw_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let mut do_ok = false;
    let mut do_cancel = false;

    egui::Window::new(tr("Change password"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(310.0, 10.0))
        .show(ctx, |ui| {
            ui.add_space(6.0);

            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.cpw_old)
                    .password(!app.cpw_show)
                    .hint_text(tr("Current password…"))
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
                    .hint_text(tr("New password… (minimum 8 characters)"))
                    .desired_width(260.0),
            );

            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.cpw_confirm)
                    .password(!app.cpw_show)
                    .hint_text(tr("Confirm new password…"))
                    .desired_width(260.0),
            );

            ui.add_space(4.0);
            ui.checkbox(&mut app.cpw_show, tr("Show passwords"));
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(
                    tr("Copies made earlier still open with the old password.\nIf it is compromised, decrypt and re-encrypt instead."),
                )
                .small()
                .weak(),
            );

            if let Some(err) = &app.cpw_error {
                ui.add_space(4.0);
                ui.colored_label(ui.visuals().error_fg_color, err);
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("  OK  ").clicked() {
                    do_ok = true;
                }
                if ui.button(tr("Cancel")).clicked() {
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

    let pq_color    = egui::Color32::from_rgb(167, 139, 250); // violet ML-KEM
    let accent_color = egui::Color32::from_rgb(80, 180, 120);

    let response = modal.show(ctx, |ui| {
        ui.set_min_width(420.0);

        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            app.show_about = false;
        }

        ui.add_space(8.0);

        // ── Titre + logo ───────────────────────────────────────────────────
        ui.vertical_centered(|ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!(
                        "../../../packaging/cryptyrust-icon.png"
                    ))
                    .fit_to_exact_size(egui::vec2(80.0, 80.0))
                    .corner_radius(10.0),
                );
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Cryptyrust").size(24.0).strong());
                    ui.label(
                        egui::RichText::new(format!(
                            "v{}  —  Antidote1911",
                            env!("CARGO_PKG_VERSION")
                        ))
                        .size(13.0)
                        .weak(),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(tr("Post-quantum file encryption"))
                            .size(12.0)
                            .weak(),
                    );
                    // Badge post-quantique
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(tr("⬡  Post-Quantum"))
                                .size(11.0)
                                .color(pq_color)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("X25519 + ML-KEM-768")
                                .size(11.0)
                                .color(pq_color)
                                .weak(),
                        );
                    });
                });
            });
        });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);

        // ── Colonne gauche : format — Colonne droite : crypto ────────────
        ui.columns(2, |cols| {
            // Colonne 1 — Format
            let ui = &mut cols[0];
            ui.label(egui::RichText::new(tr("Arsenic V2 format")).size(13.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("{}  {}", cipher_short_label(app.hdr_cipher), tr("(header)")))
                    .size(12.5),
            );
            ui.label(
                egui::RichText::new(format!("{}  {}", cipher_short_label(app.pld_cipher), tr("(payload)")))
                    .size(12.5),
            );
            ui.label(egui::RichText::new(tr("Authenticated header (BLAKE3)")).size(12.5));
            ui.label(egui::RichText::new(tr("Block streaming")).size(12.5));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(tr("Features")).size(13.0).strong());
            ui.add_space(2.0);
            let compress_txt = app.compress.map_or_else(
                || tr("Compression: off").to_string(),
                |l| trf("Compression: zstd level {l}", &[("l", &l)]),
            );
            ui.label(egui::RichText::new(compress_txt).size(12.0).weak());
            ui.label(
                egui::RichText::new(if app.armor { tr("Armor: on") } else { tr("Armor: off") })
                    .size(12.0)
                    .weak(),
            );
            ui.label(
                egui::RichText::new(tr("Multi-passphrase · Block access"))
                    .size(12.0)
                    .weak(),
            );

            // Colonne 2 — Crypto
            let ui = &mut cols[1];
            ui.label(egui::RichText::new(tr("Cryptography")).size(13.0).strong());
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Argon2id  (KDF)").size(12.5));
            ui.label(
                egui::RichText::new(tr("Interactive · Sensitive"))
                    .size(11.5)
                    .weak(),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new("X25519 + ML-KEM-768")
                    .size(12.5)
                    .color(pq_color),
            );
            ui.label(
                egui::RichText::new(match app.kem_level {
                    arsenic::KemLevel::L768  => tr("NIST level 3  (~180-bit quantum)"),
                    arsenic::KemLevel::L1024 => tr("NIST level 5  (~256-bit quantum)"),
                })
                .size(11.5)
                .color(pq_color)
                .weak(),
            );
            ui.add_space(2.0);
            ui.label(egui::RichText::new(tr("ASCII Armor — base64 transport")).size(12.0).weak());
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(6.0);

        // ── Keystore actif ─────────────────────────────────────────────────
        if !app.keys.is_empty() {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(trf(
                        if app.keys.len() > 1 {
                            tr("🔑  {n} stored keypairs")
                        } else {
                            tr("🔑  {n} stored keypair")
                        },
                        &[("n", &app.keys.len())],
                    ))
                    .size(12.0)
                    .color(accent_color),
                );
                if !app.contacts.is_empty() {
                    ui.label(
                        egui::RichText::new(format!(
                            "·  {} contact{}",
                            app.contacts.len(),
                            if app.contacts.len() > 1 { "s" } else { "" },
                        ))
                        .size(12.0)
                        .weak(),
                    );
                }
            });
            ui.add_space(4.0);
        }

        // ── Pied de page ───────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Rust • eframe / egui • NIST FIPS 203 • zstd")
                    .size(11.5)
                    .weak(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new(tr("Close")).min_size(egui::vec2(60.0, 22.0)))
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

// ── Key Manager content ───────────────────────────────────────────────────────

/// Renders the key manager content inside whatever container the caller provides
/// (viewport `CentralPanel` or legacy Window).
///
/// Sets `*close = true` when the user clicks Close or presses Escape.
/// The caller is responsible for the actual cleanup (resetting km_* state).
pub fn render_key_manager_content(app: &mut CryptyApp, ui: &mut egui::Ui, close: &mut bool) {
    // Deferred actions — collected first, applied after to avoid borrow conflicts.
    let mut do_generate = false;
    let mut do_confirm_delete: Option<usize> = None;
    let mut do_delete: Option<usize> = None;
    let mut cancel_confirm = false;
    let mut copy_text: Option<String> = None;
    let mut open_privkey_popup: Option<usize> = None;
    let mut do_export_key: Option<usize> = None;
    let mut do_add_contact = false;
    let mut do_import_contact = false;
    let mut do_confirm_delete_contact: Option<usize> = None;
    let mut do_delete_contact: Option<usize> = None;
    let mut cancel_confirm_contact = false;

    egui::ScrollArea::vertical().show(ui, |ui| {

        // ════════════════════════════════════════════════════════
        // Section 1 — My keypairs
        // ════════════════════════════════════════════════════════
        ui.label(egui::RichText::new(tr("My keypairs")).strong().size(14.0));
        ui.add_space(4.0);

        if app.keys.is_empty() {
            ui.label(egui::RichText::new(tr("No keypairs yet — generate one below.")).weak().italics());
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .min_scrolled_height(0.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(130.0).at_least(60.0).clip(true))
                .column(Column::initial(155.0).at_least(90.0).clip(true))
                .column(Column::remainder().at_least(160.0))
                .header(24.0, |mut h| {
                    h.col(|ui| { ui.label(egui::RichText::new(tr("Name")).small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new(tr("Public key")).small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Actions").small().strong()); });
                })
                .body(|mut body| {
                    for i in 0..app.keys.len() {
                        let key = &app.keys[i];
                        let short     = pubkey_short(&key.public_key);
                        let full_pub  = encode_pubkey(&key.public_key);
                        let pending   = app.km_confirm_delete == Some(i);

                        body.row(30.0, |mut row| {
                            row.col(|ui| {
                                ui.label(&key.name);
                            });
                            row.col(|ui| {
                                ui.label(egui::RichText::new(&short).monospace().weak())
                                    .on_hover_text(egui::RichText::new(&full_pub).monospace());
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button(tr("📋 Copy")).on_hover_text(tr("Copy X25519 public key")).clicked() {
                                        copy_text = Some(full_pub.clone());
                                        cancel_confirm = true;
                                    }
                                    if ui.button(tr("📤 Export"))
                                        .on_hover_text(tr("Save public key as a shareable .pubkey file"))
                                        .clicked()
                                    {
                                        do_export_key = Some(i);
                                        cancel_confirm = true;
                                    }
                                    if ui.button(tr("🔑 Secret key")).on_hover_text(tr("Reveal private key")).clicked() {
                                        open_privkey_popup = Some(i);
                                        cancel_confirm = true;
                                    }
                                    if pending {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new(tr("Confirm?")).color(egui::Color32::WHITE))
                                            .fill(egui::Color32::from_rgb(200, 60, 60)))
                                            .clicked()
                                        {
                                            do_delete = Some(i);
                                        }
                                        if ui.button(tr("Cancel")).clicked() { cancel_confirm = true; }
                                    } else if ui.add(egui::Button::new(tr("🗑 Delete")).fill(egui::Color32::TRANSPARENT)).clicked() {
                                        do_confirm_delete = Some(i);
                                    }
                                });
                            });
                        });
                    }
                });
        }

        ui.add_space(6.0);

        // Generate form
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(tr("New keypair:")).small());
            ui.add(egui::TextEdit::singleline(&mut app.km_new_name)
                .hint_text(tr("Name…"))
                .desired_width(180.0));
            if ui.button(tr("⚡ Generate")).clicked() { do_generate = true; }
        });
        if let Some(err) = &app.km_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
        } else if let Some(notice) = &app.km_notice {
            ui.colored_label(egui::Color32::from_rgb(80, 180, 80), notice);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        // ════════════════════════════════════════════════════════
        // Section 2 — Contacts
        // ════════════════════════════════════════════════════════
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Contacts").strong().size(14.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(tr("📥 Import .pubkey"))
                    .on_hover_text(
                        tr("Import a contact from a .pubkey file.\nIf the file contains a signing key it is imported too.\n(drag-and-drop also works)")
                    )
                    .clicked()
                {
                    do_import_contact = true;
                }
            });
        });
        ui.label(egui::RichText::new(tr("Import a contact's .pubkey to encrypt for them and verify their signatures.")).small().weak());
        ui.add_space(4.0);

        if app.contacts.is_empty() {
            ui.label(egui::RichText::new(tr("No contacts yet — add one below.")).weak().italics());
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .min_scrolled_height(0.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(120.0).at_least(60.0).clip(true))
                .column(Column::initial(130.0).at_least(80.0).clip(true))
                .column(Column::remainder().at_least(160.0))
                .header(24.0, |mut h| {
                    h.col(|ui| { ui.label(egui::RichText::new(tr("Name")).small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new(tr("Public key")).small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Actions").small().strong()); });
                })
                .body(|mut body| {
                    for i in 0..app.contacts.len() {
                        let c = &app.contacts[i];
                        let short    = pubkey_short(&c.public_key);
                        let full_pub = encode_pubkey(&c.public_key);
                        let pending  = app.km_confirm_delete_contact == Some(i);

                        body.row(30.0, |mut row| {
                            row.col(|ui| { ui.label(&c.name); });
                            row.col(|ui| {
                                ui.label(egui::RichText::new(&short).monospace().weak())
                                    .on_hover_text(egui::RichText::new(&full_pub).monospace());
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button(tr("📋 Copy")).on_hover_text(tr("Copy X25519 public key")).clicked() {
                                        copy_text = Some(full_pub.clone());
                                        cancel_confirm_contact = true;
                                    }
                                    if pending {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new(tr("Confirm?")).color(egui::Color32::WHITE))
                                            .fill(egui::Color32::from_rgb(200, 60, 60)))
                                            .clicked()
                                        {
                                            do_delete_contact = Some(i);
                                        }
                                        if ui.button(tr("Cancel")).clicked() { cancel_confirm_contact = true; }
                                    } else if ui.add(egui::Button::new(tr("🗑 Delete")).fill(egui::Color32::TRANSPARENT)).clicked() {
                                        do_confirm_delete_contact = Some(i);
                                    }
                                });
                            });
                        });
                    }
                });
        }

        ui.add_space(6.0);

        // Add contact form — manual entry (or use Import above / drag-and-drop)
        ui.label(egui::RichText::new(tr("Or add manually:")).small());
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_name)
                .hint_text(tr("Name…"))
                .desired_width(110.0));
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_key)
                .hint_text("arsenic1…  (X25519)")
                .font(egui::TextStyle::Monospace)
                .desired_width(180.0));
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_mlkem_key)
                .hint_text("arsenic1m…  (ML-KEM-768)")
                .font(egui::TextStyle::Monospace)
                .desired_width(200.0));
            if ui.button(tr("➕ Add")).clicked() { do_add_contact = true; }
        });
        if let Some(err) = &app.km_contact_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        // ════════════════════════════════════════════════════════

        // ── Storage paths + security warning ─────────────────────────────
        let keys_label = &app.keys_dir_label;
        let contacts_label = &app.contacts_path_label;

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("⚠").color(egui::Color32::from_rgb(220, 180, 40)).size(14.0));
            ui.label(egui::RichText::new(tr("Private keys are stored unencrypted.")).small().color(egui::Color32::from_rgb(220, 180, 40)));
        });
        ui.label(egui::RichText::new(format!("{} {keys_label}", tr("Keys:"))).small().weak().monospace());
        ui.label(egui::RichText::new(format!("Contacts: {contacts_label}")).small().weak().monospace());

        ui.add_space(8.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(tr("Close")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                *close = true;
            }
        });
        ui.add_space(4.0);
    });

    // ── Apply deferred actions ────────────────────────────────────────────────
    if cancel_confirm           { app.km_confirm_delete = None; }
    if cancel_confirm_contact   { app.km_confirm_delete_contact = None; }
    if let Some(t) = copy_text  { ui.ctx().copy_text(t); }
    if do_generate              { app.km_notice = None; app.km_generate_key(); }
    if do_add_contact           { app.km_add_contact(); }
    if do_import_contact        { app.km_import_contact_from_file(); }
    if let Some(i) = do_export_key { app.km_export_key(i); }
    if let Some(i) = do_confirm_delete         { app.km_confirm_delete = Some(i); app.km_error = None; }
    if let Some(i) = do_delete                 { app.km_delete_key(i); }
    if let Some(i) = do_confirm_delete_contact { app.km_confirm_delete_contact = Some(i); app.km_contact_error = None; }
    if let Some(i) = do_delete_contact         { app.km_delete_contact(i); }
    if let Some(i) = open_privkey_popup        { app.km_show_privkey = Some(i); }
}

/// Secret key reveal popup.  Call every frame when `app.km_show_privkey` is Some.
pub fn render_privkey_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let Some(idx) = app.km_show_privkey else { return };
    let Some(key) = app.keys.get(idx) else {
        app.km_show_privkey = None;
        return;
    };

    let name = key.name.clone();
    // The whole identity: the X25519 key alone cannot rebuild the keypair,
    // the ML-KEM seed is independent and needed to decrypt.
    let encoded = serialize_identity(key);

    let mut close = false;
    let mut copy = false;

    let warn_color = egui::Color32::from_rgb(220, 80, 60);

    egui::Window::new(trf("Secret key — {name}", &[("name", &name)]))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .min_width(480.0)
        .max_width(560.0)
        .show(ctx, |ui| {
            ui.add_space(4.0);

            // Warning banner
            egui::Frame::new()
                .fill(egui::Color32::from_rgba_unmultiplied(200, 60, 40, 40))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("⚠")
                                .color(warn_color)
                                .size(16.0),
                        );
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(tr("Never share this identity."))
                                    .color(warn_color)
                                    .strong(),
                            );
                            ui.label(
                                egui::RichText::new(
                                    tr("Anyone with this key can decrypt files encrypted for you."),
                                )
                                .color(warn_color)
                                .small(),
                            );
                        });
                    });
                });

            ui.add_space(10.0);

            // Key display — read-only selectable text so the user can select+copy manually
            ui.label(egui::RichText::new(tr("Identity file (private key + ML-KEM seed):")).strong());
            ui.label(
                egui::RichText::new(tr("Save all of it as a .key file to back up or move this keypair."))
                    .small()
                    .weak(),
            );
            ui.add_space(4.0);
            egui::Frame::new()
                .fill(ui.visuals().extreme_bg_color)
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut encoded.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(8)
                            .interactive(false),
                    );
                });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button(tr("📋 Copy to clipboard")).clicked() {
                    copy = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(tr("Close")).clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        close = true;
                    }
                });
            });
            ui.add_space(4.0);
        });

    if copy {
        ctx.copy_text(encoded);
    }
    if close {
        app.km_show_privkey = None;
    }
}

pub fn render_warning_banner(ui: &mut egui::Ui) {
    let (warn_rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::hover());
    ui.painter().text(
        warn_rect.center(),
        egui::Align2::CENTER_CENTER,
        tr("⚠  Mixed encrypted / non-encrypted files — remove files below to fix"),
        egui::FontId::proportional(12.5),
        ui.visuals().warn_fg_color,
    );
}

fn header_label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).small().strong());
}

fn render_type_cell(ui: &mut egui::Ui, is_encrypted: bool) {
    let (icon, badge) = if is_encrypted {
        ("🔒", tr("encrypted"))
    } else {
        ("📄", tr("plain"))
    };
    let resp = ui
        .horizontal(|ui| {
            ui.label(egui::RichText::new(icon).size(14.0));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(badge));
        })
        .response;
    if is_encrypted {
        resp.on_hover_text(tr("Arsenic format"));
    }
}

/// A 0–100 percentage as a 0.0–1.0 fraction.
fn pct_fraction(pct: i32) -> f32 {
    f32::from(u8::try_from(pct.clamp(0, 100)).unwrap_or(100)) / 100.0
}

/// Height of a list of `rows` rows, capped at `max`.
fn list_height(rows: usize, row_height: f32, padding: f32, max: f32) -> f32 {
    f32::from(u16::try_from(rows).unwrap_or(u16::MAX)).mul_add(row_height, padding).min(max)
}

fn render_progress_cell(ui: &mut egui::Ui, pct: i32) {
    let fraction = pct_fraction(pct);
    ui.add(
        egui::ProgressBar::new(fraction)
            .text(format!("{pct}%"))
            .desired_width(110.0),
    );
}

/// Cached type/size of `path`, read from disk only if it is not in the cache.
fn meta_of(meta: &HashMap<PathBuf, FileMeta>, path: &PathBuf) -> FileMeta {
    meta.get(path).cloned().unwrap_or_else(|| FileMeta::read(path))
}

fn remove_button(ui: &mut egui::Ui) -> bool {
    ui.add(
        egui::Button::new(egui::RichText::new("✕").size(12.0))
            .min_size(egui::vec2(20.0, 20.0))
            .fill(egui::Color32::TRANSPARENT),
    )
    .clicked()
}

pub fn render_file_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    meta: &HashMap<PathBuf, FileMeta>,
) -> Option<usize> {
    let mut to_remove: Option<usize> = None;

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto())
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().clip(true))
        .column(Column::auto())
        .header(30.0, |mut header| {
            header.col(|ui| header_label(ui, tr("Remove")));
            header.col(|ui| header_label(ui, "Type"));
            header.col(|ui| header_label(ui, tr("Name")));
            header.col(|ui| header_label(ui, tr("Size")));
        })
        .body(|body| {
            // Only the visible rows are laid out.
            body.rows(32.0, files.len(), |mut row| {
                let i = row.index();
                let path = &files[i];
                let info = meta_of(meta, path);
                row.col(|ui| {
                    if remove_button(ui) {
                        to_remove = Some(i);
                    }
                });
                row.col(|ui| render_type_cell(ui, info.encrypted));
                row.col(|ui| {
                    ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
                });
                row.col(|ui| {
                    ui.label(egui::RichText::new(&info.size).weak());
                });
            });
        });

    to_remove
}

#[allow(clippy::too_many_arguments)]
pub fn render_processing_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    meta: &HashMap<PathBuf, FileMeta>,
    progress_map: &HashMap<usize, i32>,
    statuses: &[FileStatus],
    cancel_flags: &[Arc<AtomicBool>],
    cancel_all: &Arc<AtomicBool>,
    cancellable: bool,
) {
    // "Stop all" button above the table
    let all_cancelled = cancel_all.load(Ordering::Relaxed);
    if cancellable {
        ui.horizontal(|ui| {
            if all_cancelled {
                ui.label(
                    egui::RichText::new(tr("⏹  Cancellation in progress…"))
                        .color(egui::Color32::from_rgb(220, 160, 40))
                        .small(),
                );
            } else {
                let btn = egui::Button::new(
                    egui::RichText::new(tr("⏹  Stop all tasks"))
                        .color(egui::Color32::from_rgb(220, 80, 60)),
                )
                .min_size(egui::vec2(130.0, 24.0));
                if ui.add(btn).clicked() {
                    cancel_all.store(true, Ordering::Relaxed);
                }
            }
        });
        ui.add_space(4.0);
    }

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto())
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().clip(true))
        .column(Column::auto())
        .column(Column::auto())
        .column(Column::initial(130.0).at_least(100.0))
        .header(30.0, |mut header| {
            header.col(|_ui| {});
            header.col(|ui| header_label(ui, "Type"));
            header.col(|ui| header_label(ui, tr("Name")));
            header.col(|ui| header_label(ui, tr("Size")));
            header.col(|ui| header_label(ui, tr("Progress")));
            header.col(|ui| header_label(ui, "Action"));
        })
        .body(|body| {
            body.rows(32.0, files.len(), |mut row| {
                let i = row.index();
                let path = &files[i];
                let info = meta_of(meta, path);
                let pct = progress_map.get(&i).copied().unwrap_or(0);
                let status = statuses.get(i).cloned().unwrap_or(FileStatus::Pending);
                let finished = matches!(
                    status,
                    FileStatus::Success | FileStatus::Failed(_) | FileStatus::Cancelled
                );
                let cancel_requested = all_cancelled
                    || cancel_flags.get(i).is_some_and(|f| f.load(Ordering::Relaxed));

                row.col(|ui| {
                    if matches!(status, FileStatus::Processing) && !cancel_requested {
                        ui.label(egui::RichText::new("▶").size(10.0));
                    }
                });
                row.col(|ui| render_type_cell(ui, info.encrypted));
                row.col(|ui| {
                    ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
                });
                row.col(|ui| {
                    ui.label(egui::RichText::new(&info.size).weak());
                });
                row.col(|ui| match &status {
                    FileStatus::Failed(_) => {
                        ui.label(
                            egui::RichText::new(tr("Failed"))
                                .color(ui.visuals().error_fg_color)
                                .small(),
                        );
                    }
                    FileStatus::Cancelled => {
                        ui.label(
                            egui::RichText::new(tr("Cancelled"))
                                .color(egui::Color32::from_rgb(180, 140, 60))
                                .small(),
                        );
                    }
                    _ if cancel_requested && !finished => {
                        ui.label(
                            egui::RichText::new(tr("Cancelling…"))
                                .color(egui::Color32::from_rgb(220, 160, 40))
                                .small(),
                        );
                    }
                    _ => render_progress_cell(ui, pct),
                });
                row.col(|ui| {
                    if cancellable && !finished && !cancel_requested {
                        let stop_btn = egui::Button::new(
                            egui::RichText::new(tr("⏹  Stop"))
                                .color(egui::Color32::from_rgb(220, 80, 60))
                                .small(),
                        )
                        .min_size(egui::vec2(60.0, 22.0));
                        if ui.add(stop_btn).on_hover_text(tr("Cancel this file")).clicked() {
                            if let Some(flag) = cancel_flags.get(i) {
                                flag.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                });
            });
        });
}

pub fn render_completed_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    meta: &HashMap<PathBuf, FileMeta>,
    statuses: &[FileStatus],
    success_label: &str,
) -> Option<usize> {
    let mut to_remove: Option<usize> = None;

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto())
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().clip(true))
        .column(Column::auto())
        .column(Column::initial(200.0).at_least(130.0).clip(true))
        .header(30.0, |mut header| {
            header.col(|ui| header_label(ui, tr("Remove")));
            header.col(|ui| header_label(ui, "Type"));
            header.col(|ui| header_label(ui, tr("Name")));
            header.col(|ui| header_label(ui, tr("Size")));
            header.col(|ui| header_label(ui, tr("Result")));
        })
        .body(|body| {
            body.rows(32.0, files.len().min(statuses.len()), |mut row| {
                let i = row.index();
                let path = &files[i];
                let info = meta_of(meta, path);
                row.col(|ui| {
                    if remove_button(ui) {
                        to_remove = Some(i);
                    }
                });
                row.col(|ui| render_type_cell(ui, info.encrypted));
                row.col(|ui| {
                    ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
                });
                row.col(|ui| {
                    ui.label(egui::RichText::new(&info.size).weak());
                });
                row.col(|ui| match &statuses[i] {
                    FileStatus::Success => {
                        ui.label(
                            egui::RichText::new(format!("✅  {success_label}"))
                                .color(egui::Color32::from_rgb(80, 200, 80)),
                        );
                    }
                    FileStatus::Failed(error) => {
                        ui.label(
                            egui::RichText::new(format!("❌  {error}"))
                                .color(ui.visuals().error_fg_color),
                        )
                        .on_hover_text(error);
                    }
                    FileStatus::Cancelled => {
                        ui.label(
                            egui::RichText::new(tr("⏹  Cancelled"))
                                .color(egui::Color32::from_rgb(180, 140, 60)),
                        );
                    }
                    _ => {}
                });
            });
        });

    to_remove
}
