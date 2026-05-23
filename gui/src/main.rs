#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod file_utils;
mod job;
mod pem;
mod ui;

use eframe::egui;

fn load_system_font() -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    let candidates = [
        // Noto Sans (très répandu)
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        // DejaVu (présent par défaut sur beaucoup de distros)
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        // Liberation (clone de Arial)
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        // Ubuntu
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        // Cantarell (GNOME)
        "/usr/share/fonts/cantarell/Cantarell-Regular.otf",
        "/usr/share/fonts/truetype/cantarell/Cantarell-Regular.ttf",
    ];

    #[cfg(target_os = "macos")]
    let candidates = [
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/SFNSText.ttf",
        "/Library/Fonts/Arial.ttf",
    ];

    #[cfg(target_os = "windows")]
    let candidates = [
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
    ];

    candidates.iter().find_map(|path| std::fs::read(path).ok())
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    if let Some(data) = load_system_font() {
        fonts
            .font_data
            .insert("system".to_owned(), egui::FontData::from_owned(data).into());
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "system".to_owned());
    }

    ctx.set_fonts(fonts);

    let mut style = (*ctx.global_style()).clone();
    style.text_styles = [
        (egui::TextStyle::Heading, egui::FontId::proportional(20.0)),
        (egui::TextStyle::Body, egui::FontId::proportional(15.0)),
        (egui::TextStyle::Button, egui::FontId::proportional(15.0)),
        (egui::TextStyle::Small, egui::FontId::proportional(12.0)),
        (egui::TextStyle::Monospace, egui::FontId::monospace(14.0)),
    ]
    .into();
    ctx.set_global_style(style);
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
            egui_extras::install_image_loaders(&cc.egui_ctx);
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
