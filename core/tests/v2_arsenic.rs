use cryptyrust_core::{
    arsenic::TOTAL_HEADER_LEN,
    arsenic::{decrypt_arsenic, encrypt_arsenic, ArsenicParams, BLOCK_SIZE_4MB},
    arsenic_rekey, is_arsenic_file, Secret, Ui,
};
use std::io::Cursor;
use tempfile::NamedTempFile;

struct NoUi;
impl Ui for NoUi {
    fn output(&self, _: i32) {}
}

const PASSWORD: &str = "arsenic_test_password";
const WRONG_PASSWORD: &str = "wrong_arsenic_password";

/// Minimal Argon2id params — keeps tests fast (< 1 ms KDF).
fn fast_params() -> ArsenicParams {
    ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn do_encrypt(data: &[u8]) -> Vec<u8> {
    do_encrypt_with(data, PASSWORD, fast_params())
}

fn do_encrypt_with(data: &[u8], pwd: &str, params: ArsenicParams) -> Vec<u8> {
    let mut input = Cursor::new(data);
    let mut output = Cursor::new(Vec::new());
    encrypt_arsenic(
        &mut input,
        &mut output,
        &Secret::new(pwd.into()),
        &NoUi,
        data.len() as u64,
        &params,
    )
    .expect("encrypt_arsenic failed");
    output.into_inner()
}

fn do_decrypt(ct: &[u8], pwd: &str) -> Result<Vec<u8>, cryptyrust_core::CoreErr> {
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::new());
    decrypt_arsenic(
        &mut input,
        &mut output,
        &Secret::new(pwd.into()),
        &NoUi,
        ct.len() as u64,
    )?;
    Ok(output.into_inner())
}

fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

// ── round-trip tests ──────────────────────────────────────────────────────────

#[test]
fn round_trip_small() {
    let data = b"hello arsenic world";
    let ct = do_encrypt(data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_empty() {
    let ct = do_encrypt(b"");
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn round_trip_binary_data() {
    let data: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
    let ct = do_encrypt(&data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_exactly_one_block() {
    // Exactly BLOCK_SIZE_4MB bytes — single block, no remainder
    let data = make_payload(BLOCK_SIZE_4MB);
    let ct = do_encrypt(&data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_two_blocks() {
    // One byte past the block boundary → forces a second (partial) block
    let data = make_payload(BLOCK_SIZE_4MB + 1);
    let ct = do_encrypt(&data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_two_full_blocks() {
    let data = make_payload(BLOCK_SIZE_4MB * 2);
    let ct = do_encrypt(&data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_utf8_text() {
    let text = "Données chiffrées avec Arsenic V2 — format évolutif.\n";
    let ct = do_encrypt(text.as_bytes());
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(std::str::from_utf8(&pt).unwrap(), text);
}

// ── KDF strength variants ─────────────────────────────────────────────────────

#[test]
fn round_trip_interactive_strength() {
    let params = ArsenicParams::from(cryptyrust_core::arsenic::ArsenicStrength::Interactive);
    let data = b"interactive strength round-trip";
    let ct = do_encrypt_with(data, PASSWORD, params);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

// ── wrong password ────────────────────────────────────────────────────────────

#[test]
fn wrong_password_rejected() {
    let ct = do_encrypt(b"secret data");
    // Pre-auth MAC check should reject before Argon2 even runs
    assert!(do_decrypt(&ct, WRONG_PASSWORD).is_err());
}

#[test]
fn empty_password_different_from_filled() {
    let ct = do_encrypt_with(b"data", "password", fast_params());
    assert!(do_decrypt(&ct, "").is_err());
}

// ── tampered data ─────────────────────────────────────────────────────────────

#[test]
fn tampered_header_mac_rejected() {
    let mut ct = do_encrypt(b"integrity");
    // MAC is at bytes 0x4C..0x6C (76..108)
    ct[80] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_encrypted_envelope_rejected() {
    let mut ct = do_encrypt(b"integrity");
    // Encrypted envelope at 0x6C..0xC3 (108..195)
    ct[120] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_block_body_rejected() {
    let data = make_payload(1024);
    let mut ct = do_encrypt(&data);
    // Block data starts at byte 256 (after the 256-byte header)
    let mid = 256 + ct[256..].len() / 2;
    ct[mid] ^= 0xFF;
    // Either Poly1305 tag or Merkle root check will fail
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_block_tag_rejected() {
    let data = make_payload(512);
    let mut ct = do_encrypt(&data);
    // Last 16 bytes of the file are the Poly1305 tag of the last block
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_merkle_root_accepted_wrong_block_still_fails() {
    // Tampering a block byte changes the leaf hash → Merkle check fails
    let data = make_payload(BLOCK_SIZE_4MB + 100);
    let mut ct = do_encrypt(&data);
    // Flip a byte in the first block
    ct[256 + 42] ^= 0x01;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

// ── bad magic / truncated ─────────────────────────────────────────────────────

#[test]
fn bad_magic_rejected() {
    let mut ct = do_encrypt(b"data");
    ct[0] = 0x00; // corrupt "ARSN" magic
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn truncated_header_rejected() {
    let ct = do_encrypt(b"data");
    let truncated = &ct[..64]; // less than the 256-byte header
    assert!(do_decrypt(truncated, PASSWORD).is_err());
}

#[test]
fn truncated_body_rejected() {
    let data = make_payload(8192);
    let ct = do_encrypt(&data);
    let truncated = &ct[..256 + ct[256..].len() / 2]; // half the body
    assert!(do_decrypt(truncated, PASSWORD).is_err());
}

#[test]
fn empty_file_rejected() {
    assert!(do_decrypt(&[], PASSWORD).is_err());
}

// ── is_arsenic_file detection ─────────────────────────────────────────────────

#[test]
fn is_arsenic_file_positive() {
    let data = do_encrypt(b"detect me");
    let mut tmp = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, &data).unwrap();
    assert!(is_arsenic_file(tmp.path()));
}

#[test]
fn is_arsenic_file_negative_plaintext() {
    let mut tmp = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"not a cryptyrust file at all").unwrap();
    assert!(!is_arsenic_file(tmp.path()));
}

#[test]
fn is_arsenic_file_negative_nonexistent() {
    assert!(!is_arsenic_file(std::path::Path::new(
        "/tmp/does_not_exist_xyz.arsn"
    )));
}

// ── nonce / salt randomness ───────────────────────────────────────────────────

#[test]
fn ciphertexts_are_not_deterministic() {
    let data = b"same plaintext";
    let ct1 = do_encrypt(data);
    let ct2 = do_encrypt(data);
    assert_ne!(
        ct1, ct2,
        "random salt/nonce must produce different ciphertexts"
    );
}

// ── header fields survive a round-trip ───────────────────────────────────────

#[test]
fn header_magic_present() {
    let ct = do_encrypt(b"check magic");
    assert_eq!(&ct[0..4], b"ARSN");
}

#[test]
fn header_version_correct() {
    let ct = do_encrypt(b"check version");
    assert_eq!(&ct[4..6], &[0x00, 0x02]);
}

// ── rekey (header-only password change) ──────────────────────────────────────

fn do_rekey_file(data: &[u8], old_pw: &str, new_pw: &str) -> NamedTempFile {
    // Write ciphertext to a real file so rekey can open it read+write
    let mut tmp = NamedTempFile::new().expect("tempfile");
    let ct = do_encrypt_with(data, old_pw, fast_params());
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(old_pw.into()),
        &Secret::new(new_pw.into()),
        &NoUi,
    )
    .expect("rekey failed");

    tmp
}

#[test]
fn rekey_then_decrypt_with_new_password() {
    let original = b"rekey round-trip test";
    let tmp = do_rekey_file(original, PASSWORD, "new_password_456");
    let rekeyed = std::fs::read(tmp.path()).expect("read");
    let pt = do_decrypt(&rekeyed, "new_password_456").expect("decrypt after rekey");
    assert_eq!(pt, original);
}

#[test]
fn rekey_old_password_no_longer_works() {
    let tmp = do_rekey_file(b"secret", PASSWORD, "totally_different_pw");
    let rekeyed = std::fs::read(tmp.path()).expect("read");
    assert!(
        do_decrypt(&rekeyed, PASSWORD).is_err(),
        "old password must be rejected"
    );
}

#[test]
fn rekey_wrong_old_password_rejected() {
    let ct = do_encrypt(b"some data");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    let result = arsenic_rekey(
        tmp.path(),
        &Secret::new(WRONG_PASSWORD.into()),
        &Secret::new("new_pw".into()),
        &NoUi,
    );
    assert!(result.is_err(), "wrong old password must be rejected");

    // File must be unchanged after a failed rekey
    let still_ct = std::fs::read(tmp.path()).expect("read");
    let pt = do_decrypt(&still_ct, PASSWORD).expect("file unchanged after failed rekey");
    assert_eq!(pt, b"some data");
}

#[test]
fn rekey_payload_unchanged() {
    // After rekey only the first 256 bytes (header) should differ
    let data = b"payload integrity check";
    let ct_before = do_encrypt(data);
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct_before).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("new_pw".into()),
        &NoUi,
    )
    .expect("rekey");

    let ct_after = std::fs::read(tmp.path()).expect("read");
    assert_eq!(ct_before.len(), ct_after.len(), "file size must not change");
    assert_ne!(&ct_before[..256], &ct_after[..256], "header must change");
    assert_eq!(
        &ct_before[256..],
        &ct_after[256..],
        "payload must be identical"
    );
}

#[test]
fn rekey_large_file_payload_unchanged() {
    let data = make_payload(8 * 1024 * 1024); // 8 MB (two 4MB blocks)
    let ct_before = do_encrypt_with(&data, PASSWORD, fast_params());
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct_before).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("new_pw".into()),
        &NoUi,
    )
    .expect("rekey");

    let ct_after = std::fs::read(tmp.path()).expect("read");
    assert_eq!(
        &ct_before[256..],
        &ct_after[256..],
        "payload of 8 MB file must be identical"
    );
    let pt = do_decrypt(&ct_after, "new_pw").expect("decrypt 8 MB after rekey");
    assert_eq!(pt, data);
}

// ── backup / crash-recovery tests ────────────────────────────────────────────

fn bak_path(tmp: &NamedTempFile) -> std::path::PathBuf {
    let mut name = tmp.path().file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    tmp.path().with_file_name(name)
}

#[test]
fn rekey_creates_backup_then_removes_it_on_success() {
    let ct = do_encrypt(b"backup lifecycle");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    // No backup before rekey
    assert!(!bak_path(&tmp).exists(), "no .bak before rekey");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("newpw1234".into()),
        &NoUi,
    )
    .expect("rekey");

    // Backup must be cleaned up after success
    assert!(
        !bak_path(&tmp).exists(),
        ".bak must be removed after successful rekey"
    );
}

#[test]
fn rekey_keeps_backup_on_failure() {
    let ct = do_encrypt(b"keep bak on fail");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    // Wrong old password → rekey fails after backup is written
    let _ = arsenic_rekey(
        tmp.path(),
        &Secret::new(WRONG_PASSWORD.into()),
        &Secret::new("newpw1234".into()),
        &NoUi,
    );

    // Backup must remain so the user can recover
    assert!(
        bak_path(&tmp).exists(),
        ".bak must be kept after a failed rekey"
    );

    // Backup must contain exactly 256 bytes (the original header)
    let bak = std::fs::read(bak_path(&tmp)).expect("read bak");
    assert_eq!(
        bak.len(),
        TOTAL_HEADER_LEN,
        "backup must be exactly one header"
    );

    // Main file must still be decryptable with the original password
    let still_ct = std::fs::read(tmp.path()).expect("read main");
    let pt = do_decrypt(&still_ct, PASSWORD).expect("original password must still work");
    assert_eq!(pt, b"keep bak on fail");
}

#[test]
fn rekey_stale_backup_is_silently_replaced() {
    // Simulate a previous rekey that succeeded but left a stale .bak behind.
    let ct = do_encrypt(b"stale bak scenario");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    // Write a stale backup with arbitrary 256-byte content.
    let stale_content = vec![0xAB_u8; TOTAL_HEADER_LEN];
    std::fs::write(bak_path(&tmp), &stale_content).expect("write stale bak");

    // Rekey must succeed despite the stale backup being present.
    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("newpw5678".into()),
        &NoUi,
    )
    .expect("rekey with stale bak must succeed");

    // Backup must be removed after success.
    assert!(!bak_path(&tmp).exists(), ".bak must be cleaned up");

    // File must be decryptable with the new password.
    let rekeyed = std::fs::read(tmp.path()).expect("read");
    let pt = do_decrypt(&rekeyed, "newpw5678").expect("new password must work");
    assert_eq!(pt, b"stale bak scenario");
}

#[test]
fn rekey_corrupted_header_restored_from_backup() {
    // Simulate a power cut that corrupted the first bytes of the header.
    let ct = do_encrypt(b"corruption recovery");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    // Save the genuine header as the backup (as arsenic_rekey would have done).
    let genuine_header = ct[..TOTAL_HEADER_LEN].to_vec();
    std::fs::write(bak_path(&tmp), &genuine_header).expect("write genuine bak");

    // Corrupt the first 8 bytes of the main file (wipes the "ARSN" magic).
    let mut corrupted = ct.clone();
    corrupted[..8].fill(0xFF);
    std::fs::write(tmp.path(), &corrupted).expect("write corrupted file");

    // arsenic_rekey must detect the corruption, restore, and return an error.
    let result = arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("irrelevant".into()),
        &NoUi,
    );
    assert!(
        result.is_err(),
        "must error after restoring corrupted header"
    );

    // Backup must be cleaned up after restore.
    assert!(
        !bak_path(&tmp).exists(),
        ".bak must be removed after restore"
    );

    // Main file must now be decryptable with the original password.
    let restored = std::fs::read(tmp.path()).expect("read restored");
    let pt = do_decrypt(&restored, PASSWORD).expect("file must be decryptable after restore");
    assert_eq!(pt, b"corruption recovery");
}
