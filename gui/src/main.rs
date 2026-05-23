#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod file_utils;
mod job;
mod pem;
mod ui;

use eframe::egui;

fn setup_fonts(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (egui::TextStyle::Heading, egui::FontId::proportional(20.0)),
        (egui::TextStyle::Body, egui::FontId::proportional(15.0)),
        (egui::TextStyle::Button, egui::FontId::proportional(15.0)),
        (egui::TextStyle::Small, egui::FontId::proportional(12.0)),
        (egui::TextStyle::Monospace, egui::FontId::monospace(14.0)),
    ]
    .into();
    ctx.set_style(style);
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_min_inner_size([600.0, 400.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../../packaging/cryptyrust.png"))
                    .unwrap_or_default(),
            ),
        ..Default::default()
    };

    eframe::run_native(
        "Cryptyrust",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            let system_dark = cc
                .egui_ctx
                .system_theme()
                .map(|t| t == egui::Theme::Dark)
                .unwrap_or(true);
            Ok(Box::new(app::CryptyApp::new(cc.storage, system_dark)))
        }),
    )
}
