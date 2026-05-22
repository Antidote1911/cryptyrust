use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use std::process::Command;

const ORIGINAL: &str = "tests/loremipsum.txt";

fn encrypt_file(input: &str, output: &std::path::Path, password: &str, algo: &str) {
    Command::cargo_bin("cryptyrust_cli")
        .unwrap()
        .args([
            "-e",
            input,
            "-p",
            password,
            "-s",
            "interactive",
            "-a",
            algo,
            "-o",
        ])
        .arg(output)
        .assert()
        .success();
}

fn decrypt_file(input: &std::path::Path, output: &std::path::Path, password: &str) {
    Command::cargo_bin("cryptyrust_cli")
        .unwrap()
        .arg("-d")
        .arg(input)
        .args(["-p", password, "-o"])
        .arg(output)
        .assert()
        .success();
}

fn check_roundtrip(algo: &str) {
    let temp = assert_fs::TempDir::new().unwrap();
    let encrypted = temp.child("out.crypty");
    let decrypted = temp.child("out.txt");

    encrypt_file(ORIGINAL, encrypted.path(), "testpassword", algo);
    decrypt_file(encrypted.path(), decrypted.path(), "testpassword");

    let original_bytes = std::fs::read(ORIGINAL).unwrap();
    let decrypted_bytes = std::fs::read(decrypted.path()).unwrap();
    assert_eq!(
        original_bytes, decrypted_bytes,
        "round-trip mismatch for algo={}",
        algo
    );

    temp.close().unwrap();
}

#[test]
fn roundtrip_xchacha20() {
    check_roundtrip("chacha");
}

#[test]
fn roundtrip_aesgcm() {
    check_roundtrip("aesgcm");
}

#[test]
fn roundtrip_aesgcmsiv() {
    check_roundtrip("aesgcmsiv");
}

#[test]
fn wrong_password_fails() {
    let temp = assert_fs::TempDir::new().unwrap();
    let encrypted = temp.child("out.crypty");
    let decrypted = temp.child("out.txt");

    encrypt_file(ORIGINAL, encrypted.path(), "correct_password", "aesgcm");

    Command::cargo_bin("cryptyrust_cli")
        .unwrap()
        .arg("-d")
        .arg(encrypted.path())
        .args(["-p", "wrong_password", "-o"])
        .arg(decrypted.path())
        .assert()
        .failure();

    temp.close().unwrap();
}
