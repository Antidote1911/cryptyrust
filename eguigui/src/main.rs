#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // pas de console sur Windows

mod app;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Cryptyrust")
            .with_inner_size([520.0, 400.0])
            .with_drag_and_drop(true),        // drag & drop natif
        ..Default::default()
    };
    eframe::run_native("Cryptyrust", options, Box::new(|_cc| Ok(Box::new(app::CryptyApp::default()))))
}
