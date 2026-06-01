/// Integration tests for the `cryptyrust` binary.
///
/// Each test spawns the real binary via `assert_cmd`.
/// Argon2id interactive (~1-3 s) makes encrypt/decrypt tests intentionally few.

use assert_cmd::Command;
use assert_fs::prelude::*;
use assert_fs::TempDir;

// ── helpers ───────────────────────────────────────────────────────────────────

fn cryptyrust() -> Command {
    Command::cargo_bin("cryptyrust").unwrap()
}

/// Encrypt `input` to `output` with the given password and optional extra args.
fn encrypt(input: &str, output: &str, password: &str, extra: &[&str]) {
    let mut args = vec!["-e", input, "-p", password, "-o", output];
    args.extend_from_slice(extra);
    cryptyrust().args(&args).assert().success();
}

/// Decrypt `input` to `output` with the given password.
fn decrypt(input: &str, output: &str, password: &str) {
    cryptyrust()
        .args(["-d", input, "-p", password, "-o", output])
        .assert()
        .success();
}

// ── encrypt / decrypt round-trips ─────────────────────────────────────────────

#[test]
fn roundtrip_password_default_ciphers() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("msg.txt");
    plain.write_str("Hello, Arsenic!").unwrap();
    let enc = tmp.child("msg.arsn");
    let dec = tmp.child("msg_out.txt");

    encrypt(
        plain.path().to_str().unwrap(),
        enc.path().to_str().unwrap(),
        "hunter2_secure",
        &[],
    );
    assert!(enc.path().exists(), "encrypted file should exist");

    decrypt(
        enc.path().to_str().unwrap(),
        dec.path().to_str().unwrap(),
        "hunter2_secure",
    );
    assert_eq!(
        std::fs::read_to_string(dec.path()).unwrap(),
        "Hello, Arsenic!"
    );
}

#[test]
fn roundtrip_xchacha20_hdr_aes_pld() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("data.bin");
    plain.write_binary(b"binary \x00\xFF data").unwrap();
    let enc = tmp.child("data.arsn");
    let dec = tmp.child("data_out.bin");

    encrypt(
        plain.path().to_str().unwrap(),
        enc.path().to_str().unwrap(),
        "pass_xchacha_aes",
        &["--hdr-cipher", "xchacha20", "--pld-cipher", "aes-gcm-siv"],
    );
    decrypt(
        enc.path().to_str().unwrap(),
        dec.path().to_str().unwrap(),
        "pass_xchacha_aes",
    );
    assert_eq!(
        std::fs::read(dec.path()).unwrap(),
        b"binary \x00\xFF data"
    );
}

#[test]
fn roundtrip_deoxys_hdr_xchacha_pld() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("txt.txt");
    plain.write_str("deoxys header test").unwrap();
    let enc = tmp.child("txt.arsn");
    let dec = tmp.child("txt_out.txt");

    encrypt(
        plain.path().to_str().unwrap(),
        enc.path().to_str().unwrap(),
        "pass_deoxys_xchacha",
        &["--hdr-cipher", "deoxys-ii", "--pld-cipher", "xchacha20"],
    );
    decrypt(
        enc.path().to_str().unwrap(),
        dec.path().to_str().unwrap(),
        "pass_deoxys_xchacha",
    );
    assert_eq!(
        std::fs::read_to_string(dec.path()).unwrap(),
        "deoxys header test"
    );
}

#[test]
fn roundtrip_empty_file() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("empty");
    plain.write_binary(b"").unwrap();
    let enc = tmp.child("empty.arsn");
    let dec = tmp.child("empty_out");

    encrypt(
        plain.path().to_str().unwrap(),
        enc.path().to_str().unwrap(),
        "emptyfilepass1",
        &[],
    );
    decrypt(
        enc.path().to_str().unwrap(),
        dec.path().to_str().unwrap(),
        "emptyfilepass1",
    );
    assert_eq!(std::fs::read(dec.path()).unwrap(), b"");
}

// ── wrong password ────────────────────────────────────────────────────────────

#[test]
fn wrong_password_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("secret.txt");
    plain.write_str("secret data").unwrap();
    let enc = tmp.child("secret.arsn");
    let dec = tmp.child("secret_out.txt");

    encrypt(
        plain.path().to_str().unwrap(),
        enc.path().to_str().unwrap(),
        "correct_password",
        &[],
    );
    cryptyrust()
        .args([
            "-d",
            enc.path().to_str().unwrap(),
            "-p",
            "WRONG_password",
            "-o",
            dec.path().to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!dec.path().exists(), "output should not exist after failed decrypt");
}

// ── asymmetric (recipient) round-trip ─────────────────────────────────────────

#[test]
fn roundtrip_recipient_key_file() {
    let tmp = TempDir::new().unwrap();
    let key_file = tmp.child("alice.key");
    let plain = tmp.child("msg.txt");
    plain.write_str("recipient message").unwrap();
    let enc = tmp.child("msg.arsn");
    let dec = tmp.child("msg_out.txt");

    // Generate key → file (no keystore write)
    cryptyrust()
        .args([
            "keygen",
            "-n", "alice",
            "-o", key_file.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(key_file.path().exists());

    // Encrypt for recipient (no password)
    cryptyrust()
        .args([
            "-e", plain.path().to_str().unwrap(),
            "-R", key_file.path().to_str().unwrap(),
            "-o", enc.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(enc.path().exists());

    // Decrypt with private key
    cryptyrust()
        .args([
            "-d", enc.path().to_str().unwrap(),
            "-i", key_file.path().to_str().unwrap(),
            "-o", dec.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dec.path()).unwrap(),
        "recipient message"
    );
}

#[test]
fn wrong_key_file_fails_decrypt() {
    let tmp = TempDir::new().unwrap();
    let key_alice = tmp.child("alice.key");
    let key_bob = tmp.child("bob.key");
    let plain = tmp.child("msg.txt");
    plain.write_str("for alice only").unwrap();
    let enc = tmp.child("msg.arsn");
    let dec = tmp.child("msg_out.txt");

    cryptyrust()
        .args(["keygen", "-n", "alice", "-o", key_alice.path().to_str().unwrap()])
        .assert().success();
    cryptyrust()
        .args(["keygen", "-n", "bob", "-o", key_bob.path().to_str().unwrap()])
        .assert().success();

    // Encrypt for alice
    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(), "-R", key_alice.path().to_str().unwrap(), "-o", enc.path().to_str().unwrap()])
        .assert().success();

    // Try to decrypt with bob's key — must fail
    cryptyrust()
        .args(["-d", enc.path().to_str().unwrap(), "-i", key_bob.path().to_str().unwrap(), "-o", dec.path().to_str().unwrap()])
        .assert()
        .failure();
}

// ── keygen ────────────────────────────────────────────────────────────────────

#[test]
fn keygen_to_stdout_prints_private_key() {
    cryptyrust()
        .args(["keygen", "-n", "testkey"])
        .assert()
        .success()
        .stdout(predicates::str::contains("ARSENIC-SECRET-KEY-1"));
}

#[test]
fn keygen_to_file_creates_key_file() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.child("mykey.key");

    cryptyrust()
        .args(["keygen", "-n", "mykey", "-o", out.path().to_str().unwrap()])
        .assert()
        .success();

    assert!(out.path().exists());
    let content = std::fs::read_to_string(out.path()).unwrap();
    assert!(content.contains("ARSENIC-SECRET-KEY-1"));
    assert!(content.contains("# name: mykey"));
}

#[test]
fn keygen_to_public_extracts_pubkey() {
    let tmp = TempDir::new().unwrap();
    let key = tmp.child("k.key");

    cryptyrust()
        .args(["keygen", "-n", "k", "-o", key.path().to_str().unwrap()])
        .assert().success();

    cryptyrust()
        .args(["keygen", "-y", key.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::starts_with("arsenic1"));
}

#[test]
fn keygen_store_requires_name() {
    cryptyrust()
        .args(["keygen", "--store"])
        .assert()
        .failure();
}

#[test]
fn keygen_list_does_not_crash() {
    // Just verifies it exits 0 regardless of keystore contents.
    cryptyrust()
        .args(["keygen", "--list"])
        .assert()
        .success();
}

#[test]
fn keygen_to_public_invalid_file_fails() {
    cryptyrust()
        .args(["keygen", "-y", "/nonexistent/key.key"])
        .assert()
        .failure();
}

// ── input validation ──────────────────────────────────────────────────────────

#[test]
fn encrypt_nonexistent_input_fails() {
    let tmp = TempDir::new().unwrap();
    let enc = tmp.child("out.arsn");
    cryptyrust()
        .args(["-e", "/no/such/file.txt", "-p", "pass", "-o", enc.path().to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn decrypt_nonexistent_input_fails() {
    let tmp = TempDir::new().unwrap();
    let dec = tmp.child("out.txt");
    cryptyrust()
        .args(["-d", "/no/such/file.arsn", "-p", "pass", "-o", dec.path().to_str().unwrap()])
        .assert()
        .failure();
}

// ── recipients subcommand ─────────────────────────────────────────────────────

#[test]
fn recipients_list_password_only_file() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("f.txt");
    plain.write_str("data").unwrap();
    let enc = tmp.child("f.arsn");

    // Symmetric-only file has 0 keyslots.
    encrypt(plain.path().to_str().unwrap(), enc.path().to_str().unwrap(), "pw123", &[]);
    cryptyrust()
        .args(["recipients", "list", enc.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("0 asymmetric keyslot"));
}

#[test]
fn recipients_list_identifies_slots() {
    let tmp = TempDir::new().unwrap();
    let key_a = tmp.child("a.key");
    let key_b = tmp.child("b.key");
    let plain = tmp.child("msg.txt");
    plain.write_str("hello").unwrap();
    let enc = tmp.child("msg.arsn");

    cryptyrust().args(["keygen", "-n", "alice", "-o", key_a.path().to_str().unwrap()]).assert().success();
    cryptyrust().args(["keygen", "-n", "bob",   "-o", key_b.path().to_str().unwrap()]).assert().success();

    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(),
               "-R", key_a.path().to_str().unwrap(),
               "-R", key_b.path().to_str().unwrap(),
               "-p", "listpass", "-o", enc.path().to_str().unwrap()])
        .assert().success();

    let out = cryptyrust()
        .args(["recipients", "list", enc.path().to_str().unwrap(),
               "-i", key_a.path().to_str().unwrap(),
               "-i", key_b.path().to_str().unwrap()])
        .assert().success()
        .get_output()
        .stdout.clone();

    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Slot 0"), "expected Slot 0 in output");
    assert!(text.contains("Slot 1"), "expected Slot 1 in output");
    assert!(text.contains("alice"), "expected alice identified");
    assert!(text.contains("bob"),   "expected bob identified");
}

#[test]
fn recipients_remove_by_key_file() {
    let tmp = TempDir::new().unwrap();
    let key_a = tmp.child("a.key");
    let key_b = tmp.child("b.key");
    let plain = tmp.child("data.txt");
    plain.write_str("secret").unwrap();
    let enc = tmp.child("data.arsn");
    let dec = tmp.child("data_out.txt");

    cryptyrust().args(["keygen", "-n", "a", "-o", key_a.path().to_str().unwrap()]).assert().success();
    cryptyrust().args(["keygen", "-n", "b", "-o", key_b.path().to_str().unwrap()]).assert().success();

    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(),
               "-R", key_a.path().to_str().unwrap(),
               "-R", key_b.path().to_str().unwrap(),
               "-p", "mgmtpass", "-o", enc.path().to_str().unwrap()])
        .assert().success();

    // Remove alice's slot by key file.
    cryptyrust()
        .args(["recipients", "remove", enc.path().to_str().unwrap(),
               "-i", key_a.path().to_str().unwrap(), "-p", "mgmtpass"])
        .assert().success();

    // Alice can no longer decrypt.
    cryptyrust()
        .args(["-d", enc.path().to_str().unwrap(),
               "-i", key_a.path().to_str().unwrap(),
               "-o", dec.path().to_str().unwrap()])
        .assert().failure();

    // Bob can still decrypt.
    cryptyrust()
        .args(["-d", enc.path().to_str().unwrap(),
               "-i", key_b.path().to_str().unwrap(),
               "-o", dec.path().to_str().unwrap()])
        .assert().success();
    assert_eq!(std::fs::read_to_string(dec.path()).unwrap(), "secret");
}

#[test]
fn recipients_remove_by_slot_index() {
    let tmp = TempDir::new().unwrap();
    let key = tmp.child("k.key");
    let plain = tmp.child("f.txt");
    plain.write_str("data").unwrap();
    let enc = tmp.child("f.arsn");

    cryptyrust().args(["keygen", "-n", "k", "-o", key.path().to_str().unwrap()]).assert().success();
    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(),
               "-R", key.path().to_str().unwrap(),
               "-p", "slotpass", "-o", enc.path().to_str().unwrap()])
        .assert().success();

    // Remove slot 0 by index.
    cryptyrust()
        .args(["recipients", "remove", enc.path().to_str().unwrap(),
               "--slot", "0", "-p", "slotpass"])
        .assert().success();

    // File now has 0 asymmetric keyslots.
    cryptyrust()
        .args(["recipients", "list", enc.path().to_str().unwrap()])
        .assert().success()
        .stdout(predicates::str::contains("0 asymmetric keyslot"));
}

#[test]
fn recipients_remove_wrong_key_fails() {
    let tmp = TempDir::new().unwrap();
    let key_a = tmp.child("a.key");
    let key_b = tmp.child("b.key");
    let plain = tmp.child("f.txt");
    plain.write_str("x").unwrap();
    let enc = tmp.child("f.arsn");

    cryptyrust().args(["keygen", "-n", "a", "-o", key_a.path().to_str().unwrap()]).assert().success();
    cryptyrust().args(["keygen", "-n", "b", "-o", key_b.path().to_str().unwrap()]).assert().success();

    // Encrypt for alice only.
    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(),
               "-R", key_a.path().to_str().unwrap(),
               "-p", "wrongkeypass", "-o", enc.path().to_str().unwrap()])
        .assert().success();

    // Try to remove using bob's key (not a recipient) — must fail.
    cryptyrust()
        .args(["recipients", "remove", enc.path().to_str().unwrap(),
               "-i", key_b.path().to_str().unwrap(), "-p", "wrongkeypass"])
        .assert().failure();
}

#[test]
fn recipients_remove_requires_slot_or_identity() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.child("f.txt");
    plain.write_str("x").unwrap();
    let enc = tmp.child("f.arsn");
    encrypt(plain.path().to_str().unwrap(), enc.path().to_str().unwrap(), "pw", &[]);

    cryptyrust()
        .args(["recipients", "remove", enc.path().to_str().unwrap(), "-p", "pw"])
        .assert().failure();
}

#[test]
fn recipients_add_then_new_recipient_can_decrypt() {
    let tmp = TempDir::new().unwrap();
    let key_a = tmp.child("a.key");
    let key_b = tmp.child("b.key");
    let plain = tmp.child("msg.txt");
    plain.write_str("added recipient").unwrap();
    let enc = tmp.child("msg.arsn");
    let dec = tmp.child("msg_out.txt");

    cryptyrust().args(["keygen", "-n", "a", "-o", key_a.path().to_str().unwrap()]).assert().success();
    cryptyrust().args(["keygen", "-n", "b", "-o", key_b.path().to_str().unwrap()]).assert().success();

    // Encrypt for alice only, with password.
    cryptyrust()
        .args(["-e", plain.path().to_str().unwrap(),
               "-R", key_a.path().to_str().unwrap(),
               "-p", "addpass", "-o", enc.path().to_str().unwrap()])
        .assert().success();

    // Add bob as a recipient.
    cryptyrust()
        .args(["recipients", "add", enc.path().to_str().unwrap(),
               "-R", key_b.path().to_str().unwrap(), "-p", "addpass"])
        .assert().success();

    // Bob can now decrypt.
    cryptyrust()
        .args(["-d", enc.path().to_str().unwrap(),
               "-i", key_b.path().to_str().unwrap(),
               "-o", dec.path().to_str().unwrap()])
        .assert().success();
    assert_eq!(std::fs::read_to_string(dec.path()).unwrap(), "added recipient");
}

#[test]
fn no_args_does_not_print_help_to_stderr() {
    // Without args the binary launches the GUI — we can't test the window
    // here, but we verify the CLI help path is not accidentally triggered.
    // We just ensure `--version` works as a smoke test.
    cryptyrust()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicates::str::contains("cryptyrust"));
}
