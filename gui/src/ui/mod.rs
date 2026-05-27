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

        // Action bar
        if matches!(app.job, JobState::Idle) && !app.files.is_empty() {
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
    }
}
