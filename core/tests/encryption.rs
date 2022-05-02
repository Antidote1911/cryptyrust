extern crate cryptyrust_core;

#[cfg(test)]
mod tests {
    use std::fs;

    struct ProgressUpdater {}

    impl cryptyrust_core::Ui for ProgressUpdater {
        fn output(&self, _percentage: i32) {}
    }

    #[test]
    fn compare_decrypted_to_original() -> Result<(), Box<dyn std::error::Error>> {
        let source_file_path = "filetest.bin";
        let dest_file_path = "filetest.bin.encrypted";
        let password = "a very secure password!";
        let decrypted_file_path = "filetest.bin.decrypted";

        // encrypt filetest.bin to filetest.bin.encrypted
        let config = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Encrypt,
            password.to_string(),
            Some(source_file_path.parse().unwrap()),
            Some(dest_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        // decrypt filetest.bin.encrypted to filetest.bin.decrypted
        let config = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Decrypt,
            password.to_string(),
            Some(dest_file_path.parse().unwrap()),
            Some(decrypted_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        assert_eq!(
            std::fs::read(source_file_path).unwrap(),
            std::fs::read(decrypted_file_path).unwrap()
        );
        fs::remove_file(dest_file_path).expect("could not remove file");
        fs::remove_file(decrypted_file_path).expect("could not remove file");
        Ok(())
    }

}

