use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use std::process::Command;

#[test]
fn encrypt_and_decrypt() {
    //   ./cryptyrust_cli -e test.mp4 -p 12345678
    //   ./cryptyrust_cli -d myEncryptedFile -p 12345678 -o myDecryptedFile

    let temp = assert_fs::TempDir::new().unwrap();

    let original = "tests/loremipsum.txt";

    let encrypted = temp.child("loremipsum.txt.crypty");
    let decrypted = temp.child("loremipsum (1).txt");

    let encrypted_path = encrypted.path();
    let decrypted_path = decrypted.path();

    let mut encrypt_cmd = Command::cargo_bin("cryptyrust_cli").unwrap();
    encrypt_cmd
        .arg("-e")
        .arg(original)
        .arg("-p mypassword")
        .arg("-o")
        .arg(encrypted_path);

    encrypt_cmd.assert().success();

    let mut decrypt_cmd = Command::cargo_bin("cryptyrust_cli").unwrap();
    decrypt_cmd
        .arg("-d")
        .arg(encrypted_path)
        .arg("-p mypassword")
        .arg("-o")
        .arg(decrypted_path);

    decrypt_cmd.assert().success();

    let original_bytes = std::fs::read(original).unwrap();
    let decrypted_bytes = std::fs::read(decrypted_path).unwrap();

    temp.close().unwrap();

    assert_eq!(original_bytes, decrypted_bytes);
}
