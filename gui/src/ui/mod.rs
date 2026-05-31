mod components;
mod layouts;

use eframe::egui;

use crate::app::CryptyApp;
use crate::job::{JobState, PasswordPopup};

pub struct UI;

impl UI {
    pub fn render(app: &mut CryptyApp, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let is_running = matches!(app.job, JobState::Running { .. });
        let popup_open = !matches!(app.popup, PasswordPopup::Closed);

        // Menu bar
        layouts::render_menu_bar(app, ui, is_running, popup_open);

        // Bottom bar
        layouts::render_bottom_bar(app, ui);

        // Action bar (masquée uniquement pendant le traitement)
        if !is_running {
            layouts::render_action_bar(app, ui, is_running, popup_open);
        }

        // Central panel
        layouts::render_central_panel(app, ui);

        // Popup
        if app.popup == PasswordPopup::Open {
            components::render_password_popup(app, &ctx);
        }
        if app.popup == PasswordPopup::ChangePw {
            components::render_change_pw_popup(app, &ctx);
        }

        // About window
        if app.show_about {
            components::render_about_window(app, &ctx);
        }

        // Benchmark window
        if app.show_bench {
            components::render_bench_window(app, &ctx);
        }

        // Key manager — fenêtre OS indépendante, déplaçable hors de la fenêtre principale.
        if app.show_key_manager {
            let mut close_km = false;
            let dark_mode = app.dark_mode;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("key_manager"),
                egui::ViewportBuilder::default()
                    .with_title("Key Manager")
                    .with_inner_size([660.0, 560.0])
                    .with_min_inner_size([520.0, 380.0])
                    .with_resizable(true),
                |vp_ctx, _class| {
                    // Synchroniser le thème clair/sombre avec la fenêtre principale.
                    vp_ctx.set_visuals(if dark_mode {
                        egui::Visuals::dark()
                    } else {
                        egui::Visuals::light()
                    });

                    // Fermeture via le bouton × de la barre de titre OS.
                    if vp_ctx.input(|i| i.viewport().close_requested()) {
                        close_km = true;
                    }

                    #[allow(deprecated)]
                    egui::CentralPanel::default().show(vp_ctx, |ui| {
                        components::render_key_manager_content(app, ui, &mut close_km);
                    });

                    // La popup de clé privée s'affiche dans le même viewport.
                    if app.km_show_privkey.is_some() {
                        components::render_privkey_popup(app, vp_ctx);
                    }
                },
            );
            if close_km {
                app.show_key_manager = false;
                app.km_error = None;
                app.km_confirm_delete = None;
                app.km_show_privkey = None;
                app.km_contact_error = None;
                app.km_confirm_delete_contact = None;
            }
        }
    }
}
