fn main() {
    #[cfg(target_os = "windows")]
    {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let icon = std::path::Path::new(&manifest).join("assets/icon.ico");
        winres::WindowsResource::new()
            .set_icon(icon.to_str().unwrap())
            .compile()
            .expect("Failed to compile Windows resources");
    }
}
