extern crate cryptyrust_core;

#[cfg(test)]
mod tests {
    use std::fs;
    use cryptyrust_core::{Algorithm, BenchMode, DeriveStrength, HashMode};
    use cryptyrust_core::Secret;

    struct ProgressUpdater {}

    impl cryptyrust_core::Ui for ProgressUpdater {
        fn output(&self, _percentage: i32) {}
    }

    #[test]
    fn compare_decrypted_to_original_with_aes() -> Result<(), Box<dyn std::error::Error>> {
        let source_file_path = "filetest.bin";
        let dest_file_path = "filetest.bin.encrypted.aes";
        let password = "a very secure password!";
        let decrypted_file_path = "filetest.bin.decrypted.aes";

        // encrypt filetest.bin to filetest.bin.encrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Encrypt,
            Algorithm::Aes256Gcm,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(source_file_path.parse().unwrap()),
            Some(dest_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config).unwrap();
        //assert!(cryptyrust_core::main_routine(&config).is_ok());

        // decrypt filetest.bin.encrypted to filetest.bin.decrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Decrypt,
            Algorithm::Aes256Gcm,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(dest_file_path.parse().unwrap()),
            Some(decrypted_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        assert_eq!(
            fs::read(source_file_path).unwrap(),
            fs::read(decrypted_file_path).unwrap()
        );
        fs::remove_file(dest_file_path).expect("could not remove file");
        fs::remove_file(decrypted_file_path).expect("could not remove file");
        Ok(())
    }
    #[test]
    fn compare_decrypted_to_original_with_xchacha() -> Result<(), Box<dyn std::error::Error>> {
        let source_file_path = "filetest.bin";
        let dest_file_path = "filetest.bin.encrypted.xchacha";
        let password = "a very secure password!";
        let decrypted_file_path = "filetest.bin.decrypted.xchacha";

        // encrypt filetest.bin to filetest.bin.encrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Encrypt,
            Algorithm::XChaCha20Poly1305,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(source_file_path.parse().unwrap()),
            Some(dest_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        // decrypt filetest.bin.encrypted to filetest.bin.decrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Decrypt,
            Algorithm::XChaCha20Poly1305,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(dest_file_path.parse().unwrap()),
            Some(decrypted_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        assert_eq!(
            fs::read(source_file_path).unwrap(),
            fs::read(decrypted_file_path).unwrap()
        );
        fs::remove_file(dest_file_path).expect("could not remove file");
        fs::remove_file(decrypted_file_path).expect("could not remove file");
        Ok(())
    }

    #[test]
    fn compare_decrypted_to_original_with_deoxys() -> Result<(), Box<dyn std::error::Error>> {
        let source_file_path = "filetest.bin";
        let dest_file_path = "filetest.bin.encrypted.deoxys";
        let password = "a very secure password!";
        let decrypted_file_path = "filetest.bin.decrypted.deoxys";

        // encrypt filetest.bin to filetest.bin.encrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Encrypt,
            Algorithm::DeoxysII256,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(source_file_path.parse().unwrap()),
            Some(dest_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        // decrypt filetest.bin.encrypted to filetest.bin.decrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Decrypt,
            Algorithm::DeoxysII256,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(dest_file_path.parse().unwrap()),
            Some(decrypted_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        assert_eq!(
            fs::read(source_file_path).unwrap(),
            fs::read(decrypted_file_path).unwrap()
        );
        fs::remove_file(dest_file_path).expect("could not remove file");
        fs::remove_file(decrypted_file_path).expect("could not remove file");
        Ok(())
    }

    #[test]
    fn compare_decrypted_to_original_with_aesgcmsiv() -> Result<(), Box<dyn std::error::Error>> {
        let source_file_path = "filetest.bin";
        let dest_file_path = "filetest.bin.encrypted.aesgcmsiv";
        let password = "a very secure password!";
        let decrypted_file_path = "filetest.bin.decrypted.aesgcmsiv";

        // encrypt filetest.bin to filetest.bin.encrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Encrypt,
            Algorithm::Aes256GcmSiv,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(source_file_path.parse().unwrap()),
            Some(dest_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        // decrypt filetest.bin.encrypted to filetest.bin.decrypted
        let config = cryptyrust_core::Config::new(
            cryptyrust_core::Direction::Decrypt,
            Algorithm::Aes256GcmSiv,
            DeriveStrength::Interactive,
            Secret::new(password.to_string()),
            Some(dest_file_path.parse().unwrap()),
            Some(decrypted_file_path.clone().parse().unwrap()),
            Box::new(ProgressUpdater {}),
            HashMode::NoHash,
            BenchMode::WriteToFilesystem,
        );
        cryptyrust_core::main_routine(&config)?;
        assert!(cryptyrust_core::main_routine(&config).is_ok());

        assert_eq!(
            fs::read(source_file_path).unwrap(),
            fs::read(decrypted_file_path).unwrap()
        );
        fs::remove_file(dest_file_path).expect("could not remove file");
        fs::remove_file(decrypted_file_path).expect("could not remove file");
        Ok(())
    }
}

