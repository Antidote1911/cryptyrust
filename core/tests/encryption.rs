extern crate cryptyrust_core;

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};
    use std::fs;
    use std::io::Write;

    struct ProgressUpdater {}

    impl cryptyrust_core::Ui for ProgressUpdater {
        fn output(&self, _percentage: i32) {}
    }

    #[test]
    fn wrong_password_decryption_test() -> Result<(), Box<dyn std::error::Error>> {
        // generate random file, write to temp location
        let mut random_data = vec![0; (1 << 10) * 100]; // 100KiB
        thread_rng().fill_bytes(&mut random_data);
        let mut temp_file = std::env::temp_dir();
        temp_file.push("rand.txt");
        let mut file = std::fs::File::create(&temp_file)?;
        file.write_all(&random_data)?;

        // encrypt file with 10-char password "mypassword"
        let pw = "mypassword".to_string();
        let in_file = temp_file.to_str().unwrap().to_string();
        let mut out_path = std::env::temp_dir();
        out_path.push("encrypted.txt");
        let out_file = out_path.to_str().unwrap().to_string();
        let config = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Encrypt,
            pw,
            Some(in_file),
            Some(out_file.clone()),
            Box::new(ProgressUpdater {}),
        );
        cryptyrust_core::main_routine(&config)?;

        // decrypt with an invald password. Test be ok if decryption fail.
        let pw2 = "wrongpassword".to_string();
        let c = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Decrypt,
            pw2,
            Some(out_file.clone()),
            Some("./result".to_string()),
            Box::new(ProgressUpdater {}),
        );
        assert!(cryptyrust_core::main_routine(&c).is_err());
        Ok(())
    }

    #[test]
    fn good_password_decryption_test() -> Result<(), Box<dyn std::error::Error>> {
        // generate random file, write to temp location
        let mut random_data = vec![0; (1 << 10) * 100]; // 100KiB
        thread_rng().fill_bytes(&mut random_data);
        let mut temp_file = std::env::temp_dir();
        temp_file.push("rand2.txt");
        let mut file = std::fs::File::create(&temp_file)?;
        file.write_all(&random_data)?;

        // encrypt file with 12-char password
        let pw = "mypassword".to_string();
        let in_file = temp_file.to_str().unwrap().to_string();
        let mut out_path = std::env::temp_dir();
        out_path.push("encrypted2.txt");
        let out_file = out_path.to_str().unwrap().to_string();
        let config = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Encrypt,
            pw,
            Some(in_file),
            Some(out_file.clone()),
            Box::new(ProgressUpdater {}),
        );
        cryptyrust_core::main_routine(&config)?;

        // decrypt with the correct password. Test be ok if decryption is ok.
        let pw2 = "mypassword".to_string();
        let c = cryptyrust_core::Config::new(
            &cryptyrust_core::Mode::Decrypt,
            pw2,
            Some(out_file.clone()),
            Some("./result2".to_string()),
            Box::new(ProgressUpdater {}),
        );
        assert!(cryptyrust_core::main_routine(&c).is_ok());

        fs::remove_file("./result2".to_string()).expect("could not remove file");
        Ok(())
    }
}
