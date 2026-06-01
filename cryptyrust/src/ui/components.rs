use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::app::CryptyApp;
use crate::file_utils::{
    arsenic_strength_label, cipher_label, cipher_short_label, get_file_size, is_cryptyrust_file,
    Mode,
};
use crate::job::PasswordPopup;
use arsenic::{encode_privkey, encode_pubkey};
use crate::keystore::{contacts_path, keys_dir, pubkey_short};
use arsenic::{best_combination, ArsenicStrength, CipherId, KemLevel};

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

            // ── ML-KEM level ──────────────────────────────────────────
            ui.label(egui::RichText::new("ML-KEM level").strong());
            ui.label(
                egui::RichText::new("asymmetric keyslots — encryption only")
                    .small()
                    .weak(),
            );
            ui.separator();
            ui.selectable_value(&mut app.kem_level, KemLevel::L768,
                "ML-KEM-768  (NIST level 3, ~180-bit quantum)");
            ui.selectable_value(&mut app.kem_level, KemLevel::L1024,
                "ML-KEM-1024  (NIST level 5, ~256-bit quantum)");

            ui.add_space(6.0);

            // ── ML-DSA-65 signing key ─────────────────────────────────
            ui.label(egui::RichText::new("Signing key  (ML-DSA-65)").strong());
            ui.label(
                egui::RichText::new("optional — signs encrypted files")
                    .small()
                    .weak(),
            );
            ui.separator();
            ui.selectable_value(&mut app.signing_key_index, None, "— None —");
            let n = app.signing_keys.len();
            for i in 0..n {
                let name = app.signing_keys[i].name.clone();
                ui.selectable_value(&mut app.signing_key_index, Some(i),
                    format!("✍ {name}"));
            }
            if n == 0 {
                ui.label(
                    egui::RichText::new("No signing keys — generate one in Key Manager")
                        .small().weak().italics()
                );
            }

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

pub fn render_password_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let title = match app.mode {
        Mode::Encrypt => "Encrypt",
        Mode::Decrypt => "Decrypt",
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
                "Password… (optional — recipients selected)"
            } else if pw_optional && app.mode == Mode::Decrypt {
                "Password… (optional — keypair selected)"
            } else {
                "Password…"
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
                        .hint_text("Confirm password…")
                        .desired_width(window_width - 24.0),
                );
            } else {
                // Clear confirm so it doesn't cause a mismatch when the user
                // leaves the password empty and submits.
                app.pw_confirm.clear();
            }

            ui.add_space(4.0);
            if !app.pw.is_empty() {
                ui.checkbox(&mut app.pw_show, "Show password");
            }

            // Note when encrypting without a password.
            if pw_optional && app.pw.is_empty() {
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "ℹ No password — only selected recipients can decrypt.",
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
                    ui.label(egui::RichText::new("Recipients").strong());
                    if n_sel > 0 {
                        ui.label(
                            egui::RichText::new(format!("({n_sel} selected)"))
                                .small()
                                .color(egui::Color32::from_rgb(80, 180, 80)),
                        );
                    } else {
                        ui.label(egui::RichText::new("(none — password only)").small().weak());
                    }
                });
                ui.label(
                    egui::RichText::new(
                        "Checked keys can decrypt without the password.",
                    )
                    .small()
                    .weak(),
                );
                ui.add_space(4.0);

                let n_rows = app.keys.len() + app.contacts.len();
                let scroll_h = (n_rows as f32 * 24.0 + 24.0).min(180.0);
                egui::ScrollArea::vertical()
                    .max_height(scroll_h)
                    .id_salt("pw_recipients")
                    .show(ui, |ui| {
                        // ── My keypairs ───────────────────────────────────
                        if !app.keys.is_empty() {
                            ui.label(
                                egui::RichText::new("My keypairs")
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
                        if !app.contacts.is_empty() {
                            if !app.keys.is_empty() {
                                ui.add_space(4.0);
                            }
                            ui.label(
                                egui::RichText::new("Contacts")
                                    .small()
                                    .strong()
                                    .weak(),
                            );
                            for i in 0..app.contacts.len() {
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
                    ui.label(egui::RichText::new("Decrypt with keypair").strong());
                    if app.decrypt_key_index.is_none() {
                        ui.label(egui::RichText::new("(none — use password)").small().weak());
                    }
                });
                ui.label(
                    egui::RichText::new("Select your keypair if the file was encrypted for you.")
                        .small()
                        .weak(),
                );
                ui.add_space(4.0);

                let scroll_h = (app.keys.len() as f32 * 26.0 + 8.0).min(150.0);
                egui::ScrollArea::vertical()
                    .max_height(scroll_h)
                    .id_salt("decrypt_key_sel")
                    .show(ui, |ui| {
                        // "None" option: password only
                        ui.radio_value(
                            &mut app.decrypt_key_index,
                            None,
                            egui::RichText::new("None (password only)").weak(),
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
                        egui::RichText::new("Chiffrement de fichiers post-quantique")
                            .size(12.0)
                            .weak(),
                    );
                    // Badge post-quantique
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("⬡  Post-Quantum")
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

        // ── Colonne gauche : format Arsenic — Colonne droite : crypto ─────
        ui.columns(2, |cols| {
            // Colonne 1 — Format
            let ui = &mut cols[0];
            ui.label(egui::RichText::new("Format Arsenic V1").size(13.0).strong());
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("{}  (en-tête)", cipher_short_label(app.hdr_cipher)))
                    .size(12.5),
            );
            ui.label(
                egui::RichText::new(format!("{}  (payload)", cipher_short_label(app.pld_cipher)))
                    .size(12.5),
            );
            ui.label(egui::RichText::new("BLAKE3 Merkle tree").size(12.5));
            ui.label(egui::RichText::new("Streaming par blocs").size(12.5));

            // Colonne 2 — Crypto
            let ui = &mut cols[1];
            ui.label(egui::RichText::new("Cryptographie").size(13.0).strong());
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Argon2id  (KDF)").size(12.5));
            ui.label(
                egui::RichText::new("Interactive · Sensitive")
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
                egui::RichText::new("KEM hybride post-quantique")
                    .size(11.5)
                    .color(pq_color)
                    .weak(),
            );
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(6.0);

        // ── Keystore actif ─────────────────────────────────────────────────
        if !app.keys.is_empty() {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "🔑  {} keypair{}  stocké{}",
                        app.keys.len(),
                        if app.keys.len() > 1 { "s" } else { "" },
                        if app.keys.len() > 1 { "s" } else { "" },
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
                egui::RichText::new("Rust • eframe / egui • NIST FIPS 203")
                    .size(11.5)
                    .weak(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new("Fermer").min_size(egui::vec2(60.0, 22.0)))
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
/// (viewport CentralPanel or legacy Window).
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
    let mut do_generate_signing_key = false;
    let mut do_delete_signing_key: Option<usize> = None;
    let mut do_export_sign_pubkey: Option<usize> = None;
    let mut do_import_sign_pubkey_for: Option<usize> = None;
    let mut do_import_sigpub_global = false;

    egui::ScrollArea::vertical().show(ui, |ui| {

        // ════════════════════════════════════════════════════════
        // Section 1 — My keypairs
        // ════════════════════════════════════════════════════════
        ui.label(egui::RichText::new("My keypairs").strong().size(14.0));
        ui.add_space(4.0);

        if app.keys.is_empty() {
            ui.label(egui::RichText::new("No keypairs yet — generate one below.").weak().italics());
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .min_scrolled_height(0.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(130.0).at_least(60.0).clip(true))
                .column(Column::initial(155.0).at_least(90.0).clip(true))
                .column(Column::remainder().at_least(160.0))
                .header(24.0, |mut h| {
                    h.col(|ui| { ui.label(egui::RichText::new("Name").small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Public key").small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Actions").small().strong()); });
                })
                .body(|mut body| {
                    for i in 0..app.keys.len() {
                        let key = &app.keys[i];
                        let short    = pubkey_short(&key.public_key);
                        let full_pub = encode_pubkey(&key.public_key);
                        let pending  = app.km_confirm_delete == Some(i);

                        body.row(30.0, |mut row| {
                            row.col(|ui| { ui.label(&key.name); });
                            row.col(|ui| {
                                ui.label(egui::RichText::new(&short).monospace().weak())
                                    .on_hover_text(egui::RichText::new(&full_pub).monospace());
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button("📋 Copy").on_hover_text("Copy X25519 public key").clicked() {
                                        copy_text = Some(full_pub.clone());
                                        cancel_confirm = true;
                                    }
                                    if ui.button("📤 Export")
                                        .on_hover_text("Save public key as a shareable .pubkey file")
                                        .clicked()
                                    {
                                        do_export_key = Some(i);
                                        cancel_confirm = true;
                                    }
                                    if ui.button("🔑 Secret key").on_hover_text("Reveal private key").clicked() {
                                        open_privkey_popup = Some(i);
                                        cancel_confirm = true;
                                    }
                                    if pending {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new("Confirm?").color(egui::Color32::WHITE))
                                            .fill(egui::Color32::from_rgb(200, 60, 60)))
                                            .clicked()
                                        {
                                            do_delete = Some(i);
                                        }
                                        if ui.button("Cancel").clicked() { cancel_confirm = true; }
                                    } else {
                                        if ui.add(egui::Button::new("🗑 Delete").fill(egui::Color32::TRANSPARENT)).clicked() {
                                            do_confirm_delete = Some(i);
                                        }
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
            ui.label(egui::RichText::new("New keypair:").small());
            ui.add(egui::TextEdit::singleline(&mut app.km_new_name)
                .hint_text("Name…")
                .desired_width(180.0));
            if ui.button("⚡ Generate").clicked() { do_generate = true; }
        });
        if let Some(err) = &app.km_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
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
                if ui.button("📥 Import .sigpub")
                    .on_hover_text(
                        "Import a contact's signing public key (.sigpub)\n\
                         so their signatures are recognized when decrypting"
                    )
                    .clicked()
                {
                    do_import_sigpub_global = true;
                }
                ui.add_space(4.0);
                if ui.button("📥 Import contact (.pubkey)")
                    .on_hover_text("Import a contact from a .pubkey or .key file\n(drag-and-drop also works)")
                    .clicked()
                {
                    do_import_contact = true;
                }
            });
        });
        ui.label(egui::RichText::new("Hybrid public keys received from correspondents. Ask them to export their .pubkey file.").small().weak());
        ui.add_space(4.0);

        if app.contacts.is_empty() {
            ui.label(egui::RichText::new("No contacts yet — add one below.").weak().italics());
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .min_scrolled_height(0.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(120.0).at_least(60.0).clip(true))
                .column(Column::initial(130.0).at_least(80.0).clip(true))
                .column(Column::initial(50.0))
                .column(Column::remainder().at_least(160.0))
                .header(24.0, |mut h| {
                    h.col(|ui| { ui.label(egui::RichText::new("Name").small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Public key").small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Sig ✓").small().strong())
                        .on_hover_text("Whether a trusted ML-DSA-65 signing key is attached"); });
                    h.col(|ui| { ui.label(egui::RichText::new("Actions").small().strong()); });
                })
                .body(|mut body| {
                    for i in 0..app.contacts.len() {
                        let c = &app.contacts[i];
                        let short    = pubkey_short(&c.public_key);
                        let full_pub = encode_pubkey(&c.public_key);
                        let has_sig  = c.signing_verifying_key.is_some();
                        let pending  = app.km_confirm_delete_contact == Some(i);

                        body.row(30.0, |mut row| {
                            row.col(|ui| { ui.label(&c.name); });
                            row.col(|ui| {
                                ui.label(egui::RichText::new(&short).monospace().weak())
                                    .on_hover_text(egui::RichText::new(&full_pub).monospace());
                            });
                            row.col(|ui| {
                                let (icon, color, tip) = if has_sig {
                                    ("✓", egui::Color32::from_rgb(80, 200, 100), "Signing key trusted — can verify signatures from this contact")
                                } else {
                                    ("—", ui.visuals().weak_text_color(), "No signing key — import a .sigpub to verify their signatures")
                                };
                                ui.label(egui::RichText::new(icon).color(color)).on_hover_text(tip);
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button("📋 Copy").on_hover_text("Copy X25519 public key").clicked() {
                                        copy_text = Some(full_pub.clone());
                                        cancel_confirm_contact = true;
                                    }
                                    let sig_btn = if has_sig { "🔑 Update sig key" } else { "🔑 Add sig key" };
                                    if ui.button(sig_btn)
                                        .on_hover_text("Import a .sigpub file to trust this contact's signatures")
                                        .clicked()
                                    {
                                        do_import_sign_pubkey_for = Some(i);
                                        cancel_confirm_contact = true;
                                    }
                                    if pending {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new("Confirm?").color(egui::Color32::WHITE))
                                            .fill(egui::Color32::from_rgb(200, 60, 60)))
                                            .clicked()
                                        {
                                            do_delete_contact = Some(i);
                                        }
                                        if ui.button("Cancel").clicked() { cancel_confirm_contact = true; }
                                    } else {
                                        if ui.add(egui::Button::new("🗑 Delete").fill(egui::Color32::TRANSPARENT)).clicked() {
                                            do_confirm_delete_contact = Some(i);
                                        }
                                    }
                                });
                            });
                        });
                    }
                });
        }

        ui.add_space(6.0);

        // Add contact form — manual entry (or use Import above / drag-and-drop)
        ui.label(egui::RichText::new("Or add manually:").small());
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_name)
                .hint_text("Name…")
                .desired_width(110.0));
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_key)
                .hint_text("arsenic1…  (X25519)")
                .font(egui::TextStyle::Monospace)
                .desired_width(180.0));
            ui.add(egui::TextEdit::singleline(&mut app.km_new_contact_mlkem_key)
                .hint_text("arsenic1m…  (ML-KEM-768)")
                .font(egui::TextStyle::Monospace)
                .desired_width(200.0));
            if ui.button("➕ Add").clicked() { do_add_contact = true; }
        });
        if let Some(err) = &app.km_contact_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        // ════════════════════════════════════════════════════════
        // Section 3 — Signing keys (ML-DSA-65)
        // ════════════════════════════════════════════════════════
        ui.label(egui::RichText::new("Signing keys  (ML-DSA-65)").strong().size(14.0));
        ui.label(
            egui::RichText::new(
                "NIST FIPS 204 — sign files during encryption. \
                 Recipients verify the signature automatically.",
            )
            .small()
            .weak(),
        );
        ui.add_space(4.0);

        if app.signing_keys.is_empty() {
            ui.label(
                egui::RichText::new("No signing keys yet — generate one below.")
                    .weak()
                    .italics(),
            );
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .min_scrolled_height(0.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(160.0).at_least(80.0).clip(true))
                .column(Column::remainder().at_least(120.0))
                .header(24.0, |mut h| {
                    h.col(|ui| { ui.label(egui::RichText::new("Name").small().strong()); });
                    h.col(|ui| { ui.label(egui::RichText::new("Actions").small().strong()); });
                })
                .body(|mut body| {
                    for i in 0..app.signing_keys.len() {
                        let sk = &app.signing_keys[i];
                        let active = app.signing_key_index == Some(i);
                        body.row(30.0, |mut row| {
                            row.col(|ui| {
                                let label = if active {
                                    egui::RichText::new(format!("✍ {}", sk.name)).strong()
                                } else {
                                    egui::RichText::new(&sk.name)
                                };
                                ui.label(label);
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let btn_label = if active { "★ Active" } else { "Set active" };
                                    if ui.button(btn_label)
                                        .on_hover_text("Use this key to sign encrypted files")
                                        .clicked()
                                    {
                                        app.signing_key_index =
                                            if active { None } else { Some(i) };
                                    }
                                    if ui.button("📤 Export pubkey")
                                        .on_hover_text("Save verifying key as .sigpub — share with contacts so they can verify your signatures")
                                        .clicked()
                                    {
                                        do_export_sign_pubkey = Some(i);
                                    }
                                    if ui.add(
                                        egui::Button::new("🗑 Delete")
                                            .fill(egui::Color32::TRANSPARENT),
                                    ).clicked() {
                                        do_delete_signing_key = Some(i);
                                    }
                                });
                            });
                        });
                    }
                });
        }

        ui.add_space(6.0);
        // New signing key form
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("New signing key:").small());
            ui.add(
                egui::TextEdit::singleline(&mut app.km_new_name)
                    .hint_text("Name…")
                    .desired_width(180.0),
            );
            if ui
                .button("✍ Generate")
                .on_hover_text("Generate a new ML-DSA-65 signing key")
                .clicked()
            {
                do_generate_signing_key = true;
            }
        });
        if let Some(err) = &app.km_error {
            ui.colored_label(ui.visuals().error_fg_color, err);
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(4.0);

        // ── Storage paths + security warning ─────────────────────────────
        let keys_label = keys_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let contacts_label = contacts_path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("⚠").color(egui::Color32::from_rgb(220, 180, 40)).size(14.0));
            ui.label(egui::RichText::new("Private keys are stored unencrypted.").small().color(egui::Color32::from_rgb(220, 180, 40)));
        });
        ui.label(egui::RichText::new(format!("Keys: {keys_label}")).small().weak().monospace());
        ui.label(egui::RichText::new(format!("Contacts: {contacts_label}")).small().weak().monospace());

        ui.add_space(8.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Close").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                *close = true;
            }
        });
        ui.add_space(4.0);
    });

    // ── Apply deferred actions ────────────────────────────────────────────────
    if cancel_confirm           { app.km_confirm_delete = None; }
    if cancel_confirm_contact   { app.km_confirm_delete_contact = None; }
    if let Some(t) = copy_text  { ui.ctx().copy_text(t); }
    if do_generate              { app.km_generate_key(); }
    if do_add_contact           { app.km_add_contact(); }
    if do_import_contact        { app.km_import_contact_from_file(); }
    if let Some(i) = do_export_key { app.km_export_key(i); }
    if let Some(i) = do_confirm_delete         { app.km_confirm_delete = Some(i); app.km_error = None; }
    if let Some(i) = do_delete                 { app.km_delete_key(i); }
    if let Some(i) = do_confirm_delete_contact { app.km_confirm_delete_contact = Some(i); app.km_contact_error = None; }
    if let Some(i) = do_delete_contact         { app.km_delete_contact(i); }
    if let Some(i) = open_privkey_popup        { app.km_show_privkey = Some(i); }
    if do_generate_signing_key                 { app.km_generate_signing_key(); }
    if let Some(i) = do_delete_signing_key     { app.km_delete_signing_key(i); }
    if let Some(i) = do_export_sign_pubkey     { app.km_export_sign_pubkey(i); }
    if let Some(i) = do_import_sign_pubkey_for { app.km_import_sign_pubkey_for_contact(i); }
    if do_import_sigpub_global                 { app.km_import_sigpub_global(); }
}

/// Secret key reveal popup.  Call every frame when `app.km_show_privkey` is Some.
pub fn render_privkey_popup(app: &mut CryptyApp, ctx: &egui::Context) {
    let Some(idx) = app.km_show_privkey else { return };
    let Some(key) = app.keys.get(idx) else {
        app.km_show_privkey = None;
        return;
    };

    let name = key.name.clone();
    let encoded = encode_privkey(&key.private_key);

    let mut close = false;
    let mut copy = false;

    let warn_color = egui::Color32::from_rgb(220, 80, 60);

    egui::Window::new(format!("Secret key — {name}"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .min_width(480.0)
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
                                egui::RichText::new("Never share this key.")
                                    .color(warn_color)
                                    .strong(),
                            );
                            ui.label(
                                egui::RichText::new(
                                    "Anyone with this key can decrypt files encrypted for you.",
                                )
                                .color(warn_color)
                                .small(),
                            );
                        });
                    });
                });

            ui.add_space(10.0);

            // Key display — read-only selectable text so the user can select+copy manually
            ui.label(egui::RichText::new("Private key:").strong());
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
                            .desired_rows(2)
                            .interactive(false),
                    );
                });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("📋 Copy to clipboard").clicked() {
                    copy = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close").clicked()
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
        resp.on_hover_text("Arsenic format");
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
        .column(Column::auto())
        .column(Column::auto().at_least(140.0))
        .column(Column::remainder().clip(true))
        .column(Column::auto())
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
                        ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
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
    cancel_flags: &[Arc<AtomicBool>],
    cancel_all: &Arc<AtomicBool>,
) {
    // "Stop all" button above the table
    ui.horizontal(|ui| {
        let all_cancelled = cancel_all.load(Ordering::Relaxed);
        if all_cancelled {
            ui.label(
                egui::RichText::new("⏹  Cancellation in progress…")
                    .color(egui::Color32::from_rgb(220, 160, 40))
                    .small(),
            );
        } else {
            let btn = egui::Button::new(
                egui::RichText::new("⏹  Stop all tasks").color(egui::Color32::from_rgb(220, 80, 60)),
            )
            .min_size(egui::vec2(130.0, 24.0));
            if ui.add(btn).clicked() {
                cancel_all.store(true, Ordering::Relaxed);
            }
        }
    });
    ui.add_space(4.0);

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
            header.col(|ui| {
                header_label(ui, "Type");
            });
            header.col(|ui| {
                header_label(ui, "Name");
            });
            header.col(|ui| {
                header_label(ui, "Size");
            });
            header.col(|ui| {
                header_label(ui, "Progress");
            });
            header.col(|ui| {
                header_label(ui, "Action");
            });
        })
        .body(|mut body| {
            for (i, path) in files.iter().enumerate() {
                let is_enc = is_cryptyrust_file(path);
                let pct = progress_map.get(&i).copied().unwrap_or(0);
                let is_current = i == current_idx;
                let is_cancelled = cancel_flags
                    .get(i)
                    .map(|f| f.load(Ordering::Relaxed))
                    .unwrap_or(false)
                    || cancel_all.load(Ordering::Relaxed);

                body.row(32.0, |mut row| {
                    row.col(|ui| {
                        if is_current && pct < 100 && !is_cancelled {
                            ui.label(egui::RichText::new("▶").size(10.0));
                        }
                    });
                    row.col(|ui| {
                        render_type_cell(ui, is_enc);
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(get_file_size(path)).weak());
                    });
                    row.col(|ui| {
                        if is_cancelled {
                            ui.label(
                                egui::RichText::new("Cancelling…")
                                    .color(egui::Color32::from_rgb(220, 160, 40))
                                    .small(),
                            );
                        } else {
                            render_progress_cell(ui, pct);
                        }
                    });
                    row.col(|ui| {
                        if !is_cancelled {
                            let flag = cancel_flags.get(i).cloned();
                            let stop_btn = egui::Button::new(
                                egui::RichText::new("⏹  Stop")
                                    .color(egui::Color32::from_rgb(220, 80, 60))
                                    .small(),
                            )
                            .min_size(egui::vec2(60.0, 22.0));
                            if ui.add(stop_btn).on_hover_text("Cancel this file").clicked() {
                                if let Some(flag) = flag {
                                    flag.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    });
                });
            }
        });
}

pub fn render_completed_table(
    ui: &mut egui::Ui,
    files: &[PathBuf],
    statuses: &[crate::job::FileStatus],
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
                header_label(ui, "Size");
            });
            header.col(|ui| {
                header_label(ui, "Result");
            });
        })
        .body(|mut body| {
            for (i, (path, status)) in files.iter().zip(statuses.iter()).enumerate() {
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
                        ui.label(egui::RichText::new(path.to_string_lossy().as_ref()));
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(get_file_size(path)).weak());
                    });
                    row.col(|ui| match status {
                        crate::job::FileStatus::Success => {
                            ui.label(
                                egui::RichText::new(format!("✅  {success_label}"))
                                    .color(egui::Color32::from_rgb(80, 200, 80)),
                            );
                        }
                        crate::job::FileStatus::Failed(error) => {
                            ui.label(
                                egui::RichText::new(format!("❌  {error}"))
                                    .color(ui.visuals().error_fg_color),
                            );
                        }
                        crate::job::FileStatus::Cancelled => {
                            ui.label(
                                egui::RichText::new("⏹  Cancelled")
                                    .color(egui::Color32::from_rgb(180, 140, 60)),
                            );
                        }
                        _ => {}
                    });
                });
            }
        });

    to_remove
}
