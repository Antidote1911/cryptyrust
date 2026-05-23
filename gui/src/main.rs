#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod file_utils;
mod job;
mod pem;
mod ui;

use eframe::egui;

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
            let system_dark = cc
                .egui_ctx
                .system_theme()
                .map(|t| t == egui::Theme::Dark)
                .unwrap_or(true);
            Ok(Box::new(app::CryptyApp::new(cc.storage, system_dark)))
        }),
    )
}
