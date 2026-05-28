use arsenic::{
    decrypt_arsenic, encrypt_arsenic, ArsenicParams, ArsenicStrength, CipherId, Compression, EnvelopeMetadata,
    BLOCK_SIZE_4MB, MIN_HEADER_TOTAL_SIZE, ZSTD_DEFAULT_LEVEL,
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
    fast_params_with(CipherId::DeoxysII256, CipherId::XChaCha20Poly1305)
}

fn fast_params_with(hdr: CipherId, pld: CipherId) -> ArsenicParams {
    ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
        hdr_cipher: hdr,
        pld_cipher: pld,
        metadata: EnvelopeMetadata::default(),
        compression: Compression::None,
    }
}

fn fast_params_with_metadata(meta: EnvelopeMetadata) -> ArsenicParams {
    ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
        hdr_cipher: CipherId::DeoxysII256,
        pld_cipher: CipherId::XChaCha20Poly1305,
        metadata: meta,
        compression: Compression::None,
    }
}

fn fast_params_with_compression(compression: Compression) -> ArsenicParams {
    ArsenicParams {
        t_cost: 1,
        m_cost: 64,
        p_cost: 1,
        hdr_cipher: CipherId::DeoxysII256,
        pld_cipher: CipherId::XChaCha20Poly1305,
        metadata: EnvelopeMetadata::default(),
        compression,
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

fn do_decrypt(ct: &[u8], pwd: &str) -> Result<Vec<u8>, arsenic::CoreErr> {
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

/// Decrypt and return both the plaintext and the recovered EnvelopeMetadata.
fn do_decrypt_with_meta(
    ct: &[u8],
    pwd: &str,
) -> Result<(Vec<u8>, EnvelopeMetadata), arsenic::CoreErr> {
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::new());
    let meta = decrypt_arsenic(
        &mut input,
        &mut output,
        &Secret::new(pwd.into()),
        &NoUi,
        ct.len() as u64,
    )?;
    Ok((output.into_inner(), meta))
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
    let text = "Données chiffrées avec Arsenic V1 — format évolutif.\n";
    let ct = do_encrypt(text.as_bytes());
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(std::str::from_utf8(&pt).unwrap(), text);
}

// ── KDF strength variants ─────────────────────────────────────────────────────

#[test]
fn round_trip_interactive_strength() {
    let params = ArsenicParams::from(ArsenicStrength::Interactive);
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
    // Block data starts after the header (MIN_HEADER_TOTAL_SIZE for no-metadata files)
    let hdr = MIN_HEADER_TOTAL_SIZE;
    let mid = hdr + ct[hdr..].len() / 2;
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
    // Flip a byte in the first block (starts at MIN_HEADER_TOTAL_SIZE)
    ct[MIN_HEADER_TOTAL_SIZE + 42] ^= 0x01;
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
    let hdr = MIN_HEADER_TOTAL_SIZE;
    let truncated = &ct[..hdr + ct[hdr..].len() / 2]; // half the body
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
    assert_eq!(&ct[4..6], &[0x00, 0x01]);
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
    // After rekey only the header should differ; payload bytes are identical.
    let data = b"payload integrity check";
    let ct_before = do_encrypt(data);
    let hdr = MIN_HEADER_TOTAL_SIZE; // no metadata → minimum header size
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
    assert_ne!(&ct_before[..hdr], &ct_after[..hdr], "header must change");
    assert_eq!(
        &ct_before[hdr..],
        &ct_after[hdr..],
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
        &ct_before[MIN_HEADER_TOTAL_SIZE..],
        &ct_after[MIN_HEADER_TOTAL_SIZE..],
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

    // Backup must contain exactly the original header (MIN_HEADER_TOTAL_SIZE for no-metadata files)
    let bak = std::fs::read(bak_path(&tmp)).expect("read bak");
    assert_eq!(
        bak.len(),
        MIN_HEADER_TOTAL_SIZE,
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

    // Write a stale backup with arbitrary content (same size as a TLV header).
    let stale_content = vec![0xAB_u8; MIN_HEADER_TOTAL_SIZE];
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
    let genuine_header = ct[..MIN_HEADER_TOTAL_SIZE].to_vec();
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

// ── Cipher combination round-trips ────────────────────────────────────────────

#[test]
fn round_trip_aes_gcm_siv_header_xchacha20_payload() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::XChaCha20Poly1305);
    let data = b"AES-GCM-SIV header, XChaCha20 payload";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(ct[7], 0x04, "hdr_cipher_id = AES-GCM-SIV");
    assert_eq!(ct[8], 0x03, "pld_cipher_id = XChaCha20");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_xchacha20_header_xchacha20_payload() {
    let params = fast_params_with(CipherId::XChaCha20Poly1305, CipherId::XChaCha20Poly1305);
    let data = b"XChaCha20 header and payload";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(ct[7], 0x03);
    assert_eq!(ct[8], 0x03);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_deoxys_header_aes_gcm_siv_payload() {
    let params = fast_params_with(CipherId::DeoxysII256, CipherId::Aes256GcmSiv);
    let data = b"Deoxys-II header, AES-GCM-SIV payload";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(ct[7], 0x02);
    assert_eq!(ct[8], 0x04, "pld_cipher_id = AES-GCM-SIV");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_all_aes_gcm_siv() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::Aes256GcmSiv);
    let data = b"AES-GCM-SIV everywhere";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(ct[7], 0x04);
    assert_eq!(ct[8], 0x04);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_all_deoxys() {
    let params = fast_params_with(CipherId::DeoxysII256, CipherId::DeoxysII256);
    let data = b"Deoxys-II header and payload";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_aes_gcm_siv_header_deoxys_payload() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::DeoxysII256);
    let data = b"AES-GCM-SIV header, Deoxys-II payload";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn wrong_cipher_id_rejected() {
    let mut ct = do_encrypt(b"cipher id tamper");
    // Corrupt the payload cipher ID byte to an unknown value
    ct[8] = 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn rekey_preserves_cipher_ids() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::DeoxysII256);
    let data = b"rekey cipher id preservation";
    let ct = do_encrypt_with(data, PASSWORD, params);
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("new_pw_cipher".into()),
        &NoUi,
    )
    .expect("rekey");

    let rekeyed = std::fs::read(tmp.path()).expect("read");
    // Cipher IDs must survive rekey unchanged
    assert_eq!(rekeyed[7], 0x04, "hdr_cipher_id preserved");
    assert_eq!(rekeyed[8], 0x02, "pld_cipher_id = DeoxysII256 preserved");
    assert_eq!(do_decrypt(&rekeyed, "new_pw_cipher").unwrap(), data);
}

// ── TLV envelope metadata tests ───────────────────────────────────────────────

#[test]
fn tlv_header_size_no_metadata() {
    // Without optional fields the header must be exactly MIN_HEADER_TOTAL_SIZE.
    let ct = do_encrypt(b"size check");
    assert_eq!(
        ct.len() - ct[MIN_HEADER_TOTAL_SIZE..].len(),
        MIN_HEADER_TOTAL_SIZE,
        "no-metadata header must equal MIN_HEADER_TOTAL_SIZE"
    );
    // header_total_size field at bytes 10–11
    let stored = u16::from_le_bytes([ct[10], ct[11]]) as usize;
    assert_eq!(stored, MIN_HEADER_TOTAL_SIZE);
}

#[test]
fn tlv_filename_round_trip() {
    let meta = EnvelopeMetadata {
        filename: Some("secret.txt".into()),
        ..Default::default()
    };
    let params = fast_params_with_metadata(meta);
    let data = b"file with a name";
    let ct = do_encrypt_with(data, PASSWORD, params);

    let (pt, recovered_meta) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
    assert_eq!(recovered_meta.filename.as_deref(), Some("secret.txt"));
    assert!(recovered_meta.comment.is_none());
    assert!(recovered_meta.timestamp_secs.is_none());
}

#[test]
fn tlv_comment_round_trip() {
    let meta = EnvelopeMetadata {
        comment: Some("chiffré avec Arsenic".into()),
        ..Default::default()
    };
    let ct = do_encrypt_with(b"data", PASSWORD, fast_params_with_metadata(meta));
    let (_, recovered_meta) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(
        recovered_meta.comment.as_deref(),
        Some("chiffré avec Arsenic")
    );
}

#[test]
fn tlv_timestamp_round_trip() {
    let ts: u64 = 1_700_000_000;
    let meta = EnvelopeMetadata {
        timestamp_secs: Some(ts),
        ..Default::default()
    };
    let ct = do_encrypt_with(b"timed data", PASSWORD, fast_params_with_metadata(meta));
    let (_, recovered_meta) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(recovered_meta.timestamp_secs, Some(ts));
}

#[test]
fn tlv_all_optional_fields_round_trip() {
    let meta = EnvelopeMetadata {
        filename: Some("rapport.pdf".into()),
        comment: Some("version finale".into()),
        timestamp_secs: Some(1_750_000_000),
    };
    let ct = do_encrypt_with(b"full meta", PASSWORD, fast_params_with_metadata(meta));
    let (pt, recovered) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(pt, b"full meta");
    assert_eq!(recovered.filename.as_deref(), Some("rapport.pdf"));
    assert_eq!(recovered.comment.as_deref(), Some("version finale"));
    assert_eq!(recovered.timestamp_secs, Some(1_750_000_000));
}

#[test]
fn tlv_metadata_header_larger_than_min() {
    // A filename adds 2 (tag+len) + filename.len() bytes to the header.
    let fname = "document.pdf"; // 12 bytes
    let meta = EnvelopeMetadata {
        filename: Some(fname.into()),
        ..Default::default()
    };
    let ct = do_encrypt_with(b"sized", PASSWORD, fast_params_with_metadata(meta));
    let stored = u16::from_le_bytes([ct[10], ct[11]]) as usize;
    let expected = MIN_HEADER_TOTAL_SIZE + 2 + fname.len();
    assert_eq!(
        stored, expected,
        "header_total_size must reflect filename length"
    );
}

#[test]
fn tlv_metadata_tamper_rejected() {
    // Tampering the encrypted envelope (which contains the TLV) must be caught.
    let meta = EnvelopeMetadata {
        filename: Some("important.txt".into()),
        ..Default::default()
    };
    let mut ct = do_encrypt_with(b"tamper test", PASSWORD, fast_params_with_metadata(meta));
    // Flip a byte in the encrypted envelope region (starts at PUB_HEADER_LEN = 108)
    ct[110] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tlv_metadata_preserved_after_rekey() {
    let meta = EnvelopeMetadata {
        filename: Some("kept.txt".into()),
        timestamp_secs: Some(42),
        ..Default::default()
    };
    let data = b"rekey preserves metadata";
    let ct = do_encrypt_with(data, PASSWORD, fast_params_with_metadata(meta));
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("new_pw_meta".into()),
        &NoUi,
    )
    .expect("rekey");

    let rekeyed = std::fs::read(tmp.path()).expect("read");
    let (pt, recovered) = do_decrypt_with_meta(&rekeyed, "new_pw_meta").unwrap();
    assert_eq!(pt, data);
    assert_eq!(recovered.filename.as_deref(), Some("kept.txt"));
    assert_eq!(recovered.timestamp_secs, Some(42));
}

#[test]
fn tlv_empty_metadata_no_extra_bytes() {
    // Explicitly empty optional fields must not add bytes to the header.
    let meta = EnvelopeMetadata {
        filename: Some(String::new()), // empty string → not written to TLV
        ..Default::default()
    };
    let ct_with_empty = do_encrypt_with(b"x", PASSWORD, fast_params_with_metadata(meta));
    let ct_no_meta = do_encrypt(b"x");
    let sz_with = u16::from_le_bytes([ct_with_empty[10], ct_with_empty[11]]) as usize;
    let sz_none = u16::from_le_bytes([ct_no_meta[10], ct_no_meta[11]]) as usize;
    assert_eq!(
        sz_with, sz_none,
        "empty filename must not enlarge the header"
    );
}

// ── Compression tests ─────────────────────────────────────────────────────────

#[test]
fn compression_id_zero_when_disabled() {
    let ct = do_encrypt(b"no compression");
    assert_eq!(ct[9], 0x00, "compression ID must be 0x00 when disabled");
}

#[test]
fn compression_id_one_when_zstd() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let ct = do_encrypt_with(b"compress me", PASSWORD, params);
    assert_eq!(ct[9], 0x01, "compression ID must be 0x01 for zstd");
}

#[test]
fn zstd_round_trip_small() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let data = b"hello compressed world";
    let ct = do_encrypt_with(data, PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn zstd_round_trip_empty() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let ct = do_encrypt_with(b"", PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), b"");
}

#[test]
fn zstd_round_trip_binary() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let data: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
    let ct = do_encrypt_with(&data, PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn zstd_round_trip_incompressible() {
    // Random-like data should round-trip even if compressed size > original.
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let ct = do_encrypt_with(&data, PASSWORD, params);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn zstd_compresses_repetitive_data() {
    // Highly repetitive data → ciphertext must be smaller than without compression.
    let data = vec![0x41u8; 65536]; // 64 KiB of 'A'
    let ct_plain = do_encrypt(&data);
    let ct_zstd = do_encrypt_with(
        &data,
        PASSWORD,
        fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL)),
    );
    assert!(
        ct_zstd.len() < ct_plain.len(),
        "compressed ciphertext ({} bytes) must be smaller than uncompressed ({} bytes)",
        ct_zstd.len(),
        ct_plain.len()
    );
}

#[test]
fn zstd_wrong_password_rejected() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let ct = do_encrypt_with(b"secret", PASSWORD, params);
    assert!(do_decrypt(&ct, WRONG_PASSWORD).is_err());
}

#[test]
fn zstd_tampered_block_rejected() {
    let params = fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL));
    let data = b"tamper resistance test";
    let mut ct = do_encrypt_with(data, PASSWORD, params);
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn zstd_level_range() {
    // Levels 1, 3, 9, 19 must all produce correct round-trips.
    for level in [1, 3, 9, 19] {
        let params = fast_params_with_compression(Compression::Zstd(level));
        let data = b"level range test";
        let ct = do_encrypt_with(data, PASSWORD, params);
        assert_eq!(
            do_decrypt(&ct, PASSWORD).unwrap(),
            data,
            "level {level} failed"
        );
    }
}

#[test]
fn no_compression_and_zstd_produce_different_ciphertexts() {
    let data = b"same plaintext, different params";
    let ct_plain = do_encrypt(data);
    let ct_zstd = do_encrypt_with(
        data,
        PASSWORD,
        fast_params_with_compression(Compression::Zstd(ZSTD_DEFAULT_LEVEL)),
    );
    // Different compression ID → different ciphertext (header differs at minimum)
    assert_ne!(ct_plain[9], ct_zstd[9], "compression ID must differ");
}
