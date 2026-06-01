fn main() {
    #[cfg(target_os = "windows")]
    {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        // Construire le chemin composant par composant pour éviter
        // les problèmes de séparateur avec rc.exe
        let icon = std::path::PathBuf::from(&manifest)
            .join("assets")
            .join("icon.ico");
        assert!(icon.exists(), "icon.ico introuvable : {}", icon.display());
        winres::WindowsResource::new()
            .set_icon(icon.to_str().unwrap())
            .compile()
            .expect("Failed to compile Windows resources");
    }
}
