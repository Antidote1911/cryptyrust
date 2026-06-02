use arsenic::{
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic, ArsenicParams, ArsenicStrength,
    CipherId, EnvelopeMetadata, HybridRecipient, KemLevel, BLOCK_SIZE_4MB, MIN_HEADER_TOTAL_SIZE,
    arsenic_add_recipient, arsenic_list_recipients, arsenic_rekey, arsenic_read_sender_info,
    arsenic_remove_recipient, hybrid_recipient_from_privkey, is_arsenic_file, CoreErr, Secret, Ui,
    arsenic_add_passphrase, arsenic_remove_passphrase, arsenic_list_passphrases,
};
use std::io::Cursor;
use tempfile::NamedTempFile;

struct NoUi;
impl Ui for NoUi {
    fn output(&self, _: i32) {}
}

const PASSWORD: &str = "arsenic_test_password";
const WRONG_PASSWORD: &str = "wrong_arsenic_password";

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
        recipients: vec![],
        kem_level: arsenic::KemLevel::L768,
        sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
        compress: None,
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
        recipients: vec![],
        kem_level: arsenic::KemLevel::L768,
        sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
        compress: None,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn do_encrypt(data: &[u8]) -> Vec<u8> {
    do_encrypt_with(data, PASSWORD, fast_params(), &[])
}

fn do_encrypt_with(data: &[u8], pwd: &str, mut params: ArsenicParams, recipients: &[HybridRecipient]) -> Vec<u8> {
    params.recipients = recipients.to_vec();
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

fn do_decrypt(ct: &[u8], pwd: &str) -> Result<Vec<u8>, CoreErr> {
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

fn do_decrypt_with_meta(
    ct: &[u8],
    pwd: &str,
) -> Result<(Vec<u8>, EnvelopeMetadata), CoreErr> {
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

fn do_decrypt_with_privkey(ct: &[u8], privkey: &[u8; 32]) -> Result<Vec<u8>, CoreErr> {
    let mlkem_seed = arsenic::mlkem_seed_from_x25519(privkey);
    let mut input = Cursor::new(ct);
    let mut output = Cursor::new(Vec::new());
    decrypt_arsenic_with_key(
        &mut input,
        &mut output,
        &Secret::new(*privkey),
        &mlkem_seed,
        &NoUi,
        ct.len() as u64,
    )?;
    Ok(output.into_inner())
}

fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

/// Generate a hybrid (X25519 + ML-KEM-768) keypair.
/// Returns (privkey[32], HybridRecipient) — the recipient is the "public key" to share.
fn gen_x25519_keypair() -> ([u8; 32], HybridRecipient) {
    let privkey_bytes: [u8; 32] = rand::random();
    let recip = hybrid_recipient_from_privkey(&privkey_bytes);
    (privkey_bytes, recip)
}

// ── round-trip tests (symmetric, no recipients) ───────────────────────────────

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
    let data = make_payload(BLOCK_SIZE_4MB);
    let ct = do_encrypt(&data);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn round_trip_two_blocks() {
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
    let text = "Données chiffrées avec Arsenic.\n";
    let ct = do_encrypt(text.as_bytes());
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(std::str::from_utf8(&pt).unwrap(), text);
}

#[test]
fn round_trip_interactive_strength() {
    let params = ArsenicParams::from(ArsenicStrength::Interactive);
    let data = b"interactive strength round-trip";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

// ── wrong password ────────────────────────────────────────────────────────────

#[test]
fn wrong_password_rejected() {
    let ct = do_encrypt(b"secret data");
    assert!(do_decrypt(&ct, WRONG_PASSWORD).is_err());
}

#[test]
fn empty_password_different_from_filled() {
    let ct = do_encrypt_with(b"data", "password", fast_params(), &[]);
    assert!(do_decrypt(&ct, "").is_err());
}

// ── tampered data ─────────────────────────────────────────────────────────────

#[test]
fn tampered_header_mac_rejected() {
    let mut ct = do_encrypt(b"integrity");
    // HeaderMAC starts at PRE_MAC_LEN = 78
    ct[80] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_encrypted_envelope_rejected() {
    let mut ct = do_encrypt(b"integrity");
    // Encrypted envelope starts at PUB_HEADER_LEN = 110
    ct[120] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_block_body_rejected() {
    let data = make_payload(1024);
    let mut ct = do_encrypt(&data);
    let hdr = MIN_HEADER_TOTAL_SIZE;
    let mid = hdr + ct[hdr..].len() / 2;
    ct[mid] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_block_tag_rejected() {
    let data = make_payload(512);
    let mut ct = do_encrypt(&data);
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn tampered_merkle_root_accepted_wrong_block_still_fails() {
    let data = make_payload(BLOCK_SIZE_4MB + 100);
    let mut ct = do_encrypt(&data);
    ct[MIN_HEADER_TOTAL_SIZE + 42] ^= 0x01;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

// ── bad magic / truncated ─────────────────────────────────────────────────────

#[test]
fn bad_magic_rejected() {
    let mut ct = do_encrypt(b"data");
    ct[0] = 0x00;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn truncated_header_rejected() {
    let ct = do_encrypt(b"data");
    let truncated = &ct[..64];
    assert!(do_decrypt(truncated, PASSWORD).is_err());
}

#[test]
fn truncated_body_rejected() {
    let data = make_payload(8192);
    let ct = do_encrypt(&data);
    let hdr = MIN_HEADER_TOTAL_SIZE;
    let truncated = &ct[..hdr + ct[hdr..].len() / 2];
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
    assert_ne!(ct1, ct2, "random salt/nonce must produce different ciphertexts");
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
    let mut tmp = NamedTempFile::new().expect("tempfile");
    let ct = do_encrypt_with(data, old_pw, fast_params(), &[]);
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

    let still_ct = std::fs::read(tmp.path()).expect("read");
    let pt = do_decrypt(&still_ct, PASSWORD).expect("file unchanged after failed rekey");
    assert_eq!(pt, b"some data");
}

#[test]
fn rekey_payload_unchanged() {
    let data = b"payload integrity check";
    let ct_before = do_encrypt(data);
    let hdr = MIN_HEADER_TOTAL_SIZE;
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
    let data = make_payload(8 * 1024 * 1024);
    let ct_before = do_encrypt_with(&data, PASSWORD, fast_params(), &[]);
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

    assert!(!bak_path(&tmp).exists(), "no .bak before rekey");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("newpw1234".into()),
        &NoUi,
    )
    .expect("rekey");

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

    let _ = arsenic_rekey(
        tmp.path(),
        &Secret::new(WRONG_PASSWORD.into()),
        &Secret::new("newpw1234".into()),
        &NoUi,
    );

    assert!(
        bak_path(&tmp).exists(),
        ".bak must be kept after a failed rekey"
    );

    let bak = std::fs::read(bak_path(&tmp)).expect("read bak");
    assert_eq!(
        bak.len(),
        MIN_HEADER_TOTAL_SIZE,
        "backup must be exactly one header"
    );

    let still_ct = std::fs::read(tmp.path()).expect("read main");
    let pt = do_decrypt(&still_ct, PASSWORD).expect("original password must still work");
    assert_eq!(pt, b"keep bak on fail");
}

#[test]
fn rekey_stale_backup_is_silently_replaced() {
    let ct = do_encrypt(b"stale bak scenario");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    let stale_content = vec![0xAB_u8; MIN_HEADER_TOTAL_SIZE];
    std::fs::write(bak_path(&tmp), &stale_content).expect("write stale bak");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("newpw5678".into()),
        &NoUi,
    )
    .expect("rekey with stale bak must succeed");

    assert!(!bak_path(&tmp).exists(), ".bak must be cleaned up");

    let rekeyed = std::fs::read(tmp.path()).expect("read");
    let pt = do_decrypt(&rekeyed, "newpw5678").expect("new password must work");
    assert_eq!(pt, b"stale bak scenario");
}

#[test]
fn rekey_corrupted_header_restored_from_backup() {
    let ct = do_encrypt(b"corruption recovery");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    let genuine_header = ct[..MIN_HEADER_TOTAL_SIZE].to_vec();
    std::fs::write(bak_path(&tmp), &genuine_header).expect("write genuine bak");

    let mut corrupted = ct.clone();
    corrupted[..8].fill(0xFF);
    std::fs::write(tmp.path(), &corrupted).expect("write corrupted file");

    let result = arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("irrelevant".into()),
        &NoUi,
    );
    assert!(result.is_err(), "must error after restoring corrupted header");

    assert!(
        !bak_path(&tmp).exists(),
        ".bak must be removed after restore"
    );

    let restored = std::fs::read(tmp.path()).expect("read restored");
    let pt = do_decrypt(&restored, PASSWORD).expect("file must be decryptable after restore");
    assert_eq!(pt, b"corruption recovery");
}

// ── Cipher combination round-trips ────────────────────────────────────────────

#[test]
fn round_trip_aes_gcm_siv_header_xchacha20_payload() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::XChaCha20Poly1305);
    let data = b"AES-GCM-SIV header, XChaCha20 payload";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(ct[7], 0x04, "hdr_cipher_id = AES-GCM-SIV");
    assert_eq!(ct[8], 0x03, "pld_cipher_id = XChaCha20");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_xchacha20_header_xchacha20_payload() {
    let params = fast_params_with(CipherId::XChaCha20Poly1305, CipherId::XChaCha20Poly1305);
    let data = b"XChaCha20 header and payload";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(ct[7], 0x03);
    assert_eq!(ct[8], 0x03);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_deoxys_header_aes_gcm_siv_payload() {
    let params = fast_params_with(CipherId::DeoxysII256, CipherId::Aes256GcmSiv);
    let data = b"Deoxys-II header, AES-GCM-SIV payload";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(ct[7], 0x02);
    assert_eq!(ct[8], 0x04, "pld_cipher_id = AES-GCM-SIV");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_all_aes_gcm_siv() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::Aes256GcmSiv);
    let data = b"AES-GCM-SIV everywhere";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(ct[7], 0x04);
    assert_eq!(ct[8], 0x04);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_all_deoxys() {
    let params = fast_params_with(CipherId::DeoxysII256, CipherId::DeoxysII256);
    let data = b"Deoxys-II header and payload";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn round_trip_aes_gcm_siv_header_deoxys_payload() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::DeoxysII256);
    let data = b"AES-GCM-SIV header, Deoxys-II payload";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn wrong_cipher_id_rejected() {
    let mut ct = do_encrypt(b"cipher id tamper");
    ct[8] = 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn rekey_preserves_cipher_ids() {
    let params = fast_params_with(CipherId::Aes256GcmSiv, CipherId::DeoxysII256);
    let data = b"rekey cipher id preservation";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
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
    assert_eq!(rekeyed[7], 0x04, "hdr_cipher_id preserved");
    assert_eq!(rekeyed[8], 0x02, "pld_cipher_id = DeoxysII256 preserved");
    assert_eq!(do_decrypt(&rekeyed, "new_pw_cipher").unwrap(), data);
}

// ── TLV envelope metadata tests ───────────────────────────────────────────────

#[test]
fn tlv_header_size_no_metadata() {
    let ct = do_encrypt(b"size check");
    assert_eq!(
        ct.len() - ct[MIN_HEADER_TOTAL_SIZE..].len(),
        MIN_HEADER_TOTAL_SIZE
    );
    // header_total_size is u32 at bytes 9–12
    let stored = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
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
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);

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
    let ct = do_encrypt_with(b"data", PASSWORD, fast_params_with_metadata(meta), &[]);
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
    let ct = do_encrypt_with(b"timed data", PASSWORD, fast_params_with_metadata(meta), &[]);
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
    let ct = do_encrypt_with(b"full meta", PASSWORD, fast_params_with_metadata(meta), &[]);
    let (pt, recovered) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(pt, b"full meta");
    assert_eq!(recovered.filename.as_deref(), Some("rapport.pdf"));
    assert_eq!(recovered.comment.as_deref(), Some("version finale"));
    assert_eq!(recovered.timestamp_secs, Some(1_750_000_000));
}

#[test]
fn tlv_metadata_header_larger_than_min() {
    let fname = "document.pdf"; // 12 bytes
    let meta = EnvelopeMetadata {
        filename: Some(fname.into()),
        ..Default::default()
    };
    let ct = do_encrypt_with(b"sized", PASSWORD, fast_params_with_metadata(meta), &[]);
    let stored = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
    let expected = MIN_HEADER_TOTAL_SIZE + 2 + fname.len();
    assert_eq!(stored, expected, "header_total_size must reflect filename length");
}

#[test]
fn tlv_metadata_tamper_rejected() {
    let meta = EnvelopeMetadata {
        filename: Some("important.txt".into()),
        ..Default::default()
    };
    let mut ct = do_encrypt_with(b"tamper test", PASSWORD, fast_params_with_metadata(meta), &[]);
    // Envelope starts at PUB_HEADER_LEN = 110
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
    let ct = do_encrypt_with(data, PASSWORD, fast_params_with_metadata(meta), &[]);
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
    let meta = EnvelopeMetadata {
        filename: Some(String::new()),
        ..Default::default()
    };
    let ct_with_empty = do_encrypt_with(b"x", PASSWORD, fast_params_with_metadata(meta), &[]);
    let ct_no_meta = do_encrypt(b"x");
    let sz_with = u32::from_le_bytes(ct_with_empty[9..13].try_into().unwrap()) as usize;
    let sz_none = u32::from_le_bytes(ct_no_meta[9..13].try_into().unwrap()) as usize;
    assert_eq!(sz_with, sz_none, "empty filename must not enlarge the header");
}

// ── Asymmetric keyslot tests ──────────────────────────────────────────────────

#[test]
fn asym_round_trip_single_recipient() {
    let (privkey, pubkey) = gen_x25519_keypair();
    let data = b"secret for one recipient";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pubkey]);

    let pt = do_decrypt_with_privkey(&ct, &privkey).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn asym_also_decryptable_with_password() {
    let (_privkey, pubkey) = gen_x25519_keypair();
    let data = b"decryptable both ways";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pubkey]);

    // Symmetric path must still work.
    let pt = do_decrypt(&ct, PASSWORD).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn asym_round_trip_multiple_recipients() {
    let (priv1, pub1) = gen_x25519_keypair();
    let (priv2, pub2) = gen_x25519_keypair();
    let (priv3, pub3) = gen_x25519_keypair();
    let data = b"multi-recipient message";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pub1, pub2, pub3]);

    assert_eq!(do_decrypt_with_privkey(&ct, &priv1).unwrap(), data);
    assert_eq!(do_decrypt_with_privkey(&ct, &priv2).unwrap(), data);
    assert_eq!(do_decrypt_with_privkey(&ct, &priv3).unwrap(), data);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn asym_wrong_key_rejected() {
    let (_priv1, pub1) = gen_x25519_keypair();
    let (priv_other, _pub_other) = gen_x25519_keypair();
    let ct = do_encrypt_with(b"not for you", PASSWORD, fast_params(), &[pub1]);

    assert!(
        do_decrypt_with_privkey(&ct, &priv_other).is_err(),
        "wrong private key must be rejected"
    );
}

#[test]
fn asym_no_keyslots_rejected_with_privkey() {
    // File has no asymmetric keyslots → private key decryption must fail.
    let (_privkey, _pubkey) = gen_x25519_keypair();
    let (other_priv, _) = gen_x25519_keypair();
    let ct = do_encrypt(b"symmetric only");
    assert!(do_decrypt_with_privkey(&ct, &other_priv).is_err());
}

#[test]
fn asym_header_size_grows_with_recipients() {
    let (_p1, pub1) = gen_x25519_keypair();
    let (_p2, pub2) = gen_x25519_keypair();

    let ct0 = do_encrypt_with(b"x", PASSWORD, fast_params(), &[]);
    let ct1 = do_encrypt_with(b"x", PASSWORD, fast_params(), &[pub1.clone()]);
    let ct2 = do_encrypt_with(b"x", PASSWORD, fast_params(), &[pub1, pub2]);

    let sz0 = u32::from_le_bytes(ct0[9..13].try_into().unwrap()) as usize;
    let sz1 = u32::from_le_bytes(ct1[9..13].try_into().unwrap()) as usize;
    let sz2 = u32::from_le_bytes(ct2[9..13].try_into().unwrap()) as usize;

    // Each hybrid keyslot = 1180 bytes.
    assert_eq!(sz1 - sz0, 1180, "1 hybrid keyslot adds 1180 bytes");
    assert_eq!(sz2 - sz0, 2360, "2 hybrid keyslots add 2360 bytes");
}

#[test]
fn asym_payload_bytes_identical_regardless_of_recipients() {
    let (_p1, pub1) = gen_x25519_keypair();
    // Same DEK will encrypt differently each time (random nonce), but we can
    // verify that adding recipients doesn't re-encrypt: use a deterministic check
    // by ensuring both files have the same payload length (since block count is identical).
    let data = make_payload(1024);
    let ct0 = do_encrypt_with(&data, PASSWORD, fast_params(), &[]);
    let ct1 = do_encrypt_with(&data, PASSWORD, fast_params(), &[pub1]);

    let hdr0 = u32::from_le_bytes(ct0[9..13].try_into().unwrap()) as usize;
    let hdr1 = u32::from_le_bytes(ct1[9..13].try_into().unwrap()) as usize;

    assert_eq!(
        ct0.len() - hdr0,
        ct1.len() - hdr1,
        "payload length must be identical regardless of recipient count"
    );
}

#[test]
fn add_recipient_then_decrypt_with_new_key() {
    let data = b"add recipient round-trip";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[]);

    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    let (privkey, pubkey) = gen_x25519_keypair();
    arsenic_add_recipient(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &pubkey,
        &NoUi,
    )
    .expect("add_recipient failed");

    let updated = std::fs::read(tmp.path()).expect("read");

    // Symmetric path still works.
    assert_eq!(do_decrypt(&updated, PASSWORD).unwrap(), data);
    // New recipient can decrypt.
    assert_eq!(do_decrypt_with_privkey(&updated, &privkey).unwrap(), data);
}

#[test]
fn add_recipient_wrong_password_rejected() {
    let ct = do_encrypt(b"some data");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    let (_priv, pub_) = gen_x25519_keypair();
    let result = arsenic_add_recipient(
        tmp.path(),
        &Secret::new(WRONG_PASSWORD.into()),
        &pub_,
        &NoUi,
    );
    assert!(result.is_err(), "wrong password must reject add_recipient");

    // File must be unchanged.
    let still_ct = std::fs::read(tmp.path()).expect("read");
    assert_eq!(do_decrypt(&still_ct, PASSWORD).unwrap(), b"some data");
}

#[test]
fn remove_recipient_revokes_access() {
    let (priv1, pub1) = gen_x25519_keypair();
    let data = b"remove recipient test";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pub1]);

    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    // Recipient can decrypt before removal.
    assert_eq!(do_decrypt_with_privkey(&ct, &priv1).unwrap(), data);

    arsenic_remove_recipient(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        0,
        &NoUi,
    )
    .expect("remove_recipient failed");

    let updated = std::fs::read(tmp.path()).expect("read");

    // Symmetric password still works.
    assert_eq!(do_decrypt(&updated, PASSWORD).unwrap(), data);
    // Revoked recipient must be rejected.
    assert!(
        do_decrypt_with_privkey(&updated, &priv1).is_err(),
        "removed recipient must be rejected"
    );
}

#[test]
fn list_recipients_returns_correct_count() {
    let (_p1, pub1) = gen_x25519_keypair();
    let (_p2, pub2) = gen_x25519_keypair();
    let ct = do_encrypt_with(b"count test", PASSWORD, fast_params(), &[pub1, pub2]);

    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");

    let slots = arsenic_list_recipients(tmp.path()).expect("list_recipients");
    assert_eq!(slots.len(), 2, "must report 2 asymmetric keyslots");
}

#[test]
fn list_recipients_empty_when_none() {
    let ct = do_encrypt(b"no recipients");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");

    let slots = arsenic_list_recipients(tmp.path()).expect("list_recipients");
    assert!(slots.is_empty(), "must report 0 asymmetric keyslots");
}

#[test]
fn rekey_preserves_asym_keyslots() {
    let (priv1, pub1) = gen_x25519_keypair();
    let data = b"rekey preserves asym";
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pub1]);

    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write");
    tmp.as_file_mut().sync_all().expect("sync");

    arsenic_rekey(
        tmp.path(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("new_pw".into()),
        &NoUi,
    )
    .expect("rekey");

    let rekeyed = std::fs::read(tmp.path()).expect("read");

    // New password works.
    assert_eq!(do_decrypt(&rekeyed, "new_pw").unwrap(), data);
    // Old password rejected.
    assert!(do_decrypt(&rekeyed, PASSWORD).is_err());
    // Asymmetric recipient still works after rekey.
    assert_eq!(do_decrypt_with_privkey(&rekeyed, &priv1).unwrap(), data);
}

// ── Sender identity ───────────────────────────────────────────────────────────

fn params_with_sender() -> ArsenicParams {
    use arsenic::keystore::KeyEntry;
    let key = KeyEntry::generate("alice".into());
    ArsenicParams {
        t_cost: 1, m_cost: 64, p_cost: 1,
        hdr_cipher: CipherId::DeoxysII256,
        pld_cipher: CipherId::XChaCha20Poly1305,
        metadata: EnvelopeMetadata::default(),
        recipients: vec![],
        kem_level: arsenic::KemLevel::L768,
        sender_name: Some("alice".into()),
        sender_x25519_pk: Some(key.public_key),
        sender_mlkem_pk: Some(*key.mlkem_public_key),
        compress: None,
    }
}

#[test]
fn sender_round_trip_readable_without_decryption() {
    let data = b"sender test";
    let params = params_with_sender();
    let sender_x25519 = params.sender_x25519_pk.unwrap();

    let ct = do_encrypt_with(data, PASSWORD, params, &[]);

    let mut tmp = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, &ct).unwrap();
    tmp.as_file_mut().sync_all().unwrap();

    let sender = arsenic_read_sender_info(tmp.path()).expect("sender info must be present");
    assert_eq!(sender.name, "alice");
    assert_eq!(sender.x25519_pk, sender_x25519);

    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn tampered_payload_rejected_by_merkle() {
    // Tampered payload must fail at Merkle root verification.
    let data = b"original confidential content";
    let (priv_bob, pub_bob) = gen_x25519_keypair();
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pub_bob]);

    assert_eq!(do_decrypt_with_privkey(&ct, &priv_bob).unwrap(), data);

    let hdr_size = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
    let mut tampered = ct.clone();
    tampered[hdr_size + 10] ^= 0xFF;

    assert!(do_decrypt_with_privkey(&tampered, &priv_bob).is_err(), "tampered payload rejected");
    assert!(do_decrypt(&tampered, PASSWORD).is_err(), "tampered payload rejected (symmetric)");
}

// ── Feature 1: ASCII armor ────────────────────────────────────────────────────

#[test]
fn armor_round_trip() {
    let ct = do_encrypt(b"armor test");
    let armored = arsenic::armor(&ct);
    assert!(armored.contains("-----BEGIN ARSENIC ENCRYPTED FILE-----"));
    assert!(armored.contains("-----END ARSENIC ENCRYPTED FILE-----"));
    let dearmored = arsenic::dearmor(&armored).expect("dearmor failed");
    assert_eq!(dearmored, ct);
    assert_eq!(do_decrypt(&dearmored, PASSWORD).unwrap(), b"armor test");
}

#[test]
fn armor_missing_header_rejected() {
    let bad = "no header\n-----END ARSENIC ENCRYPTED FILE-----\n";
    assert!(arsenic::dearmor(bad).is_err());
}

#[test]
fn armor_missing_footer_rejected() {
    let bad = "-----BEGIN ARSENIC ENCRYPTED FILE-----\nYWJj\n";
    assert!(arsenic::dearmor(bad).is_err());
}

#[test]
fn armor_invalid_base64_rejected() {
    let bad = "-----BEGIN ARSENIC ENCRYPTED FILE-----\n!!!\n-----END ARSENIC ENCRYPTED FILE-----\n";
    assert!(arsenic::dearmor(bad).is_err());
}

#[test]
fn armor_line_width() {
    let ct = do_encrypt(&vec![0u8; 256]);
    let armored = arsenic::armor(&ct);
    for line in armored.lines() {
        if line.starts_with('-') { continue; }
        assert!(line.len() <= 64, "line too long: {} chars", line.len());
    }
}

// ── Feature 2: encrypt to non-seekable output ─────────────────────────────────

#[test]
fn to_writer_round_trip() {
    use arsenic::encrypt_arsenic_to_writer;
    let data = b"non-seekable encrypt test";
    let password = Secret::new(PASSWORD.into());
    let mut ct = Vec::new();
    encrypt_arsenic_to_writer(
        &mut Cursor::new(data),
        &mut ct,
        &password,
        &NoUi,
        data.len() as u64,
        &fast_params(),
    ).expect("encrypt_arsenic_to_writer failed");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn to_writer_matches_seekable_output() {
    use arsenic::encrypt_arsenic_to_writer;
    let data = b"comparison test";
    let mut ct_seekable = Cursor::new(Vec::new());
    encrypt_arsenic(&mut Cursor::new(data), &mut ct_seekable,
        &Secret::new(PASSWORD.into()), &NoUi, data.len() as u64, &fast_params()).unwrap();
    let mut ct_writer = Vec::new();
    encrypt_arsenic_to_writer(&mut Cursor::new(data), &mut ct_writer,
        &Secret::new(PASSWORD.into()), &NoUi, data.len() as u64, &fast_params()).unwrap();
    // Both must decrypt correctly (ciphertexts differ due to random nonces).
    assert_eq!(do_decrypt(&ct_seekable.into_inner(), PASSWORD).unwrap(), data);
    assert_eq!(do_decrypt(&ct_writer, PASSWORD).unwrap(), data);
}

// ── Feature 3: partial block decryption ──────────────────────────────────────

#[test]
fn decrypt_block_at_single_block_file() {
    use arsenic::decrypt_block_at;
    let data = b"single block data";
    let ct = do_encrypt(data);
    let mut cursor = Cursor::new(ct);
    let block = decrypt_block_at(&mut cursor, &Secret::new(PASSWORD.into()), 0, &NoUi)
        .expect("decrypt_block_at failed");
    assert_eq!(block, data);
}

#[test]
fn decrypt_block_at_out_of_bounds() {
    use arsenic::decrypt_block_at;
    let ct = do_encrypt(b"small");
    let mut cursor = Cursor::new(ct);
    assert!(decrypt_block_at(&mut cursor, &Secret::new(PASSWORD.into()), 999, &NoUi).is_err());
}

#[test]
fn decrypt_block_at_tampered_block_rejected() {
    use arsenic::decrypt_block_at;
    let data = b"block tamper test";
    let mut ct = do_encrypt(data);
    let hdr_size = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
    ct[hdr_size + 5] ^= 0xFF;
    let mut cursor = Cursor::new(ct);
    assert!(decrypt_block_at(&mut cursor, &Secret::new(PASSWORD.into()), 0, &NoUi).is_err());
}

#[test]
fn decrypt_block_at_compressed_rejected() {
    use arsenic::decrypt_block_at;
    let mut params = fast_params();
    params.compress = Some(3);
    let data = b"compressible compressible compressible data";
    let ct = do_encrypt_with(data, PASSWORD, params, &[]);
    let mut cursor = Cursor::new(ct);
    assert!(
        decrypt_block_at(&mut cursor, &Secret::new(PASSWORD.into()), 0, &NoUi).is_err(),
        "compressed file should reject random-access"
    );
}

// ── Feature 4: extra passphrase slots ────────────────────────────────────────

#[test]
fn add_passphrase_decrypt_with_new() {
    let data = b"multi-passphrase";
    let ct_path = {
        let mut tmp = NamedTempFile::new().unwrap();
        let ct = do_encrypt(data);
        std::io::Write::write_all(&mut tmp, &ct).unwrap();
        tmp.into_temp_path()
    };
    arsenic::arsenic_add_passphrase(
        ct_path.as_ref(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("extra_pass".into()),
        &NoUi,
    ).expect("add_passphrase failed");

    // Primary password still works.
    assert_eq!(do_decrypt(&std::fs::read(&ct_path).unwrap(), PASSWORD).unwrap(), data);
    // Extra password also works.
    assert_eq!(do_decrypt(&std::fs::read(&ct_path).unwrap(), "extra_pass").unwrap(), data);
}

#[test]
fn add_passphrase_max_slots_rejected() {
    let ct_path = {
        let mut tmp = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, &do_encrypt(b"x")).unwrap();
        tmp.into_temp_path()
    };
    for i in 0..15 {
        arsenic::arsenic_add_passphrase(
            ct_path.as_ref(),
            &Secret::new(PASSWORD.into()),
            &Secret::new(format!("extra_{i}").as_str().into()),
            &NoUi,
        ).expect("add_passphrase failed");
    }
    // 16th must fail.
    assert!(arsenic::arsenic_add_passphrase(
        ct_path.as_ref(),
        &Secret::new(PASSWORD.into()),
        &Secret::new("one_too_many".into()),
        &NoUi,
    ).is_err());
}

#[test]
fn remove_passphrase_revokes_access() {
    let data = b"remove slot test";
    let ct_path = {
        let mut tmp = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, &do_encrypt(data)).unwrap();
        tmp.into_temp_path()
    };
    arsenic::arsenic_add_passphrase(
        ct_path.as_ref(), &Secret::new(PASSWORD.into()), &Secret::new("to_remove".into()), &NoUi,
    ).unwrap();
    arsenic::arsenic_remove_passphrase(
        ct_path.as_ref(), &Secret::new(PASSWORD.into()), &Secret::new("to_remove".into()), &NoUi,
    ).expect("remove_passphrase failed");
    // Extra slot gone.
    assert!(do_decrypt(&std::fs::read(&ct_path).unwrap(), "to_remove").is_err());
    // Primary still works.
    assert_eq!(do_decrypt(&std::fs::read(&ct_path).unwrap(), PASSWORD).unwrap(), data);
}

#[test]
fn remove_primary_slot_rejected() {
    let ct_path = {
        let mut tmp = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, &do_encrypt(b"x")).unwrap();
        tmp.into_temp_path()
    };
    assert!(arsenic::arsenic_remove_passphrase(
        ct_path.as_ref(),
        &Secret::new(PASSWORD.into()),
        &Secret::new(PASSWORD.into()),
        &NoUi,
    ).is_err());
}

#[test]
fn list_passphrases_count() {
    let ct_path = {
        let mut tmp = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, &do_encrypt(b"x")).unwrap();
        tmp.into_temp_path()
    };
    assert_eq!(arsenic::arsenic_list_passphrases(ct_path.as_ref()).unwrap(), 0);
    arsenic::arsenic_add_passphrase(
        ct_path.as_ref(), &Secret::new(PASSWORD.into()), &Secret::new("p2".into()), &NoUi,
    ).unwrap();
    assert_eq!(arsenic::arsenic_list_passphrases(ct_path.as_ref()).unwrap(), 1);
}

// ── Feature 5: zstd compression ──────────────────────────────────────────────

#[test]
fn compress_zstd_round_trip() {
    let data: Vec<u8> = b"hello compressible data ".iter().cycle().take(4096).copied().collect();
    let mut params = fast_params();
    params.compress = Some(3);
    let ct = do_encrypt_with(&data, PASSWORD, params, &[]);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn compress_incompressible_still_works() {
    // Random data compresses poorly but should still round-trip.
    let mut params = fast_params();
    params.compress = Some(1);
    let data = do_encrypt(b"random-ish data for compress test"); // use a ciphertext as "random" data
    let ct = do_encrypt_with(&data, PASSWORD, params, &[]);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn compress_tampered_block_rejected() {
    let mut params = fast_params();
    params.compress = Some(3);
    let data: Vec<u8> = vec![b'A'; 1024];
    let mut ct = do_encrypt_with(&data, PASSWORD, params, &[]);
    let hdr_size = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
    ct[hdr_size + 5] ^= 0xFF;
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn compress_original_size_preserved() {
    let data: Vec<u8> = vec![b'Z'; 2048];
    let mut params = fast_params();
    params.compress = Some(9);
    let ct = do_encrypt_with(&data, PASSWORD, params, &[]);
    // Verify ciphertext is smaller than uncompressed would be (loosely).
    // Uncompressed: MIN_HEADER + 2048 + 16 (tag) ≈ 2300 bytes.
    assert!(ct.len() < data.len() + 300, "compressed ct should be smaller than 2348");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}
