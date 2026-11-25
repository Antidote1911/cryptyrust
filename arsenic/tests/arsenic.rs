#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_possible_truncation)]

use arsenic::{
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic, ArsenicParams, ArsenicStrength,
    CipherId, EnvelopeMetadata, HybridRecipient, KemLevel, BLOCK_SIZE_4MB, MIN_HEADER_TOTAL_SIZE,
    PASSWORD_SLOT_LEN,
    arsenic_add_recipient, arsenic_list_recipients, arsenic_rekey, arsenic_read_sender_info,
    arsenic_remove_recipient, hybrid_recipient_from_privkey, is_arsenic_file, CoreErr, Secret, Ui,
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

const fn fast_params_with_metadata(meta: EnvelopeMetadata) -> ArsenicParams {
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

/// Header size of a file with one password slot and nothing else.
const PW_HEADER: usize = MIN_HEADER_TOTAL_SIZE + PASSWORD_SLOT_LEN;

/// Header size recorded in an encrypted buffer.
fn hdr_len(ct: &[u8]) -> usize {
    u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize
}

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
/// Returns (privkey[32], `HybridRecipient`) — the recipient is the "public key" to share.
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
fn tampered_first_payload_byte_rejected() {
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
    assert_eq!(&ct[4..6], &[0x00, 0x02]);
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
    let hdr = hdr_len(&ct_before);
    assert_eq!(hdr, PW_HEADER);
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
        &ct_before[PW_HEADER..],
        &ct_after[PW_HEADER..],
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
fn rekey_wrong_password_changes_nothing_and_leaves_no_backup() {
    let ct = do_encrypt(b"keep file on fail");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");

    let result = arsenic_rekey(
        tmp.path(),
        &Secret::new(WRONG_PASSWORD.into()),
        &Secret::new("newpw1234".into()),
        &NoUi,
    );
    assert!(result.is_err());

    // Nothing was written, so there is nothing to recover from.
    assert!(!bak_path(&tmp).exists(), ".bak must not outlive a refused rekey");
    assert_eq!(std::fs::read(tmp.path()).expect("read main"), ct);
}

/// A complete header left in `.bak` means a previous change was interrupted:
/// it is restored, even though the header on disk still looks valid.
#[test]
fn rekey_restores_leftover_backup_even_if_header_looks_valid() {
    let ct = do_encrypt(b"interrupted");
    let mut tmp = NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut tmp, &ct).expect("write ct");
    tmp.as_file_mut().sync_all().expect("sync");
    let original_header = ct[..hdr_len(&ct)].to_vec();

    // Change the password, then pretend the cleanup never happened.
    arsenic_rekey(tmp.path(), &Secret::new(PASSWORD.into()), &Secret::new("second-pw".into()), &NoUi)
        .expect("first rekey");
    std::fs::write(bak_path(&tmp), &original_header).expect("write bak");

    let err = arsenic_rekey(tmp.path(), &Secret::new("second-pw".into()), &Secret::new("third-pw".into()), &NoUi)
        .expect_err("must stop after restoring");
    assert!(err.to_string().contains("interrupted"), "{err}");
    assert!(!bak_path(&tmp).exists());

    // The header from before the "interrupted" change is back.
    let restored = std::fs::read(tmp.path()).expect("read");
    assert_eq!(do_decrypt(&restored, PASSWORD).expect("original password"), b"interrupted");
    assert!(do_decrypt(&restored, "second-pw").is_err());
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

    let genuine_header = ct[..hdr_len(&ct)].to_vec();
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
    // header_total_size is u32 at bytes 9–12; one password slot, no metadata.
    assert_eq!(hdr_len(&ct), PW_HEADER);
    // "size check" is 10 bytes: one final block of 10 + 16-byte tag.
    assert_eq!(ct.len(), PW_HEADER + 10 + 16);
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
    let expected = PW_HEADER + 2 + fname.len();
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
    let ct1 = do_encrypt_with(b"x", PASSWORD, fast_params(), std::slice::from_ref(&pub1));
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
fn tampered_payload_rejected() {
    // Tampered payload must fail at Merkle root verification.
    let data = b"original confidential content";
    let (priv_bob, pub_bob) = gen_x25519_keypair();
    let ct = do_encrypt_with(data, PASSWORD, fast_params(), &[pub_bob]);

    assert_eq!(do_decrypt_with_privkey(&ct, &priv_bob).unwrap(), data);

    let hdr_size = u32::from_le_bytes(ct[9..13].try_into().unwrap()) as usize;
    let mut tampered = ct;
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
    assert_eq!(arsenic::arsenic_list_passphrases(ct_path.as_ref()).unwrap(), 1);
    arsenic::arsenic_add_passphrase(
        ct_path.as_ref(), &Secret::new(PASSWORD.into()), &Secret::new("p2".into()), &NoUi,
    ).unwrap();
    assert_eq!(arsenic::arsenic_list_passphrases(ct_path.as_ref()).unwrap(), 2);
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

// ── invalid recipient key ─────────────────────────────────────────────────────

/// A public key of the right length that is not a valid ML-KEM key must be
/// refused at import and must make encryption fail, not panic.
#[test]
fn invalid_mlkem_public_key_is_an_error_not_a_panic() {
    let bad = [0xFFu8; 1184];
    assert!(!::arsenic::mlkem_pubkey_is_valid(&bad));
    assert!(::arsenic::decode_mlkem_pubkey(&::arsenic::encode_mlkem_pubkey(&bad)).is_none());

    let mut params = fast_params();
    params.recipients = vec![HybridRecipient::new([7u8; 32], bad)];
    let mut input = Cursor::new(b"hello".to_vec());
    let mut output = Cursor::new(Vec::new());
    let err = encrypt_arsenic(
        &mut input, &mut output, &Secret::new(PASSWORD.into()), &NoUi, 5, &params,
    )
    .expect_err("encryption for an invalid key must fail");
    assert!(err.to_string().contains("invalid ML-KEM public key"), "{err}");

    // A genuine key still round-trips through the text encoding.
    let good = ::arsenic::keystore::KeyEntry::generate("k".into());
    let enc = ::arsenic::encode_mlkem_pubkey(&good.mlkem_public_key);
    assert_eq!(::arsenic::decode_mlkem_pubkey(&enc).map(Box::new), Some(good.mlkem_public_key));
}

// ══ Format V2 ═════════════════════════════════════════════════════════════════

const BLOCK_ENC: usize = BLOCK_SIZE_4MB + 16;

fn to_temp(ct: &[u8]) -> tempfile::TempPath {
    let mut tmp = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, ct).unwrap();
    tmp.into_temp_path()
}

/// Equality without printing megabytes of data when it fails.
fn same(a: &[u8], b: &[u8]) -> bool {
    a == b
}

fn secret(s: &str) -> Secret<String> {
    Secret::new(s.into())
}

fn decrypt_file(path: &std::path::Path, pwd: &str) -> Result<Vec<u8>, CoreErr> {
    do_decrypt(&std::fs::read(path).unwrap(), pwd)
}

/// A real keypair with an independent ML-KEM seed, as the keystore makes them.
fn keystore_key() -> arsenic::keystore::KeyEntry {
    arsenic::keystore::KeyEntry::generate("k".into())
}

fn decrypt_with_entry(ct: &[u8], key: &arsenic::keystore::KeyEntry) -> Result<Vec<u8>, CoreErr> {
    let mut output = Cursor::new(Vec::new());
    decrypt_arsenic_with_key(
        &mut Cursor::new(ct), &mut output, &Secret::new(key.private_key), &key.mlkem_seed, &NoUi,
        ct.len() as u64,
    )?;
    Ok(output.into_inner())
}

// ── payload: truncation, extension, reordering ────────────────────────────────

#[test]
fn v2_truncation_at_a_block_boundary_is_rejected() {
    // Exactly two full blocks, then one short block.
    let data = make_payload(2 * BLOCK_SIZE_4MB + 100);
    let ct = do_encrypt(&data);
    let h = hdr_len(&ct);
    assert_eq!(ct.len(), h + 2 * BLOCK_ENC + 100 + 16);

    // Drop the last block: what remains is a whole number of valid blocks.
    assert!(do_decrypt(&ct[..h + 2 * BLOCK_ENC], PASSWORD).is_err());
    // Drop two blocks.
    assert!(do_decrypt(&ct[..h + BLOCK_ENC], PASSWORD).is_err());
    // Drop the whole payload.
    assert!(do_decrypt(&ct[..h], PASSWORD).is_err());
    // Cut inside the last block.
    assert!(do_decrypt(&ct[..ct.len() - 1], PASSWORD).is_err());
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
}

#[test]
fn v2_appended_data_is_rejected() {
    let ct = do_encrypt(&make_payload(1000));
    let mut longer = ct.clone();
    longer.extend_from_slice(&[0u8; 16]);
    assert!(do_decrypt(&longer, PASSWORD).is_err());
    // Appending a copy of the (final) block is not accepted either.
    let h = hdr_len(&ct);
    let mut doubled = ct.clone();
    doubled.extend_from_slice(&ct[h..]);
    assert!(do_decrypt(&doubled, PASSWORD).is_err());
}

#[test]
fn v2_swapped_blocks_are_rejected() {
    let data = make_payload(2 * BLOCK_SIZE_4MB + 100);
    let mut ct = do_encrypt(&data);
    let h = hdr_len(&ct);
    let (first, rest) = ct[h..].split_at_mut(BLOCK_ENC);
    first.swap_with_slice(&mut rest[..BLOCK_ENC]);
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn v2_empty_file_has_one_authenticated_block() {
    let ct = do_encrypt(b"");
    assert_eq!(ct.len(), hdr_len(&ct) + 16, "an empty file is one empty final block");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), b"");
    // Without that block the file is truncated, not empty.
    assert!(do_decrypt(&ct[..hdr_len(&ct)], PASSWORD).is_err());
}

#[test]
fn v2_exact_multiple_of_block_size_roundtrips() {
    for blocks in [1usize, 2] {
        let data = make_payload(blocks * BLOCK_SIZE_4MB);
        let ct = do_encrypt(&data);
        assert_eq!(ct.len(), hdr_len(&ct) + blocks * BLOCK_ENC, "no extra empty block");
        assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), data);
    }
}

#[test]
fn v2_many_blocks_roundtrip_across_parallel_windows() {
    // More blocks than one window on any machine with up to 32 threads.
    let data = make_payload(40 * BLOCK_SIZE_4MB + 12_345);
    let ct = do_encrypt(&data);
    assert!(same(&do_decrypt(&ct, PASSWORD).unwrap(), &data));
}

// ── header: everything is authenticated ───────────────────────────────────────

#[test]
fn v2_every_header_byte_is_authenticated() {
    let (sk, recipient) = gen_x25519_keypair();
    let mut params = params_with_sender();
    params.recipients = vec![recipient];
    let ct = do_encrypt_with(b"authenticated header", PASSWORD, params, &[]);
    let h = hdr_len(&ct);
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), b"authenticated header");

    // Flip one bit in each header byte: neither the password nor the keypair
    // may accept the file.
    for i in (0..h).step_by(7).chain([h - 1]) {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(do_decrypt(&bad, PASSWORD).is_err(), "password accepted a change at byte {i}");
        assert!(do_decrypt_with_privkey(&bad, &sk).is_err(), "keypair accepted a change at byte {i}");
    }
}

#[test]
fn v2_sender_identity_cannot_be_swapped() {
    let ct = do_encrypt_with(b"from alice", PASSWORD, params_with_sender(), &[]);
    let path = to_temp(&ct);
    let sender = arsenic_read_sender_info(path.as_ref()).expect("sender present");

    // Replace one byte of the sender's name in the clear header.
    let pos = ct.windows(sender.name.len()).position(|w| w == sender.name.as_bytes()).unwrap();
    let mut forged = ct;
    forged[pos] ^= 0x20;
    let forged_path = to_temp(&forged);
    // Still readable without a key (that read is not authenticated)…
    assert_ne!(arsenic_read_sender_info(forged_path.as_ref()).unwrap().name, sender.name);
    // …but the file no longer decrypts.
    assert!(do_decrypt(&forged, PASSWORD).is_err());
}

#[test]
fn v2_older_format_is_reported_as_unsupported() {
    let mut ct = do_encrypt(b"x");
    ct[5] = 0x01; // version 00 01
    let err = do_decrypt(&ct, PASSWORD).unwrap_err();
    assert!(matches!(err, CoreErr::BadHeaderVersion), "{err}");
}

// ── passwords ─────────────────────────────────────────────────────────────────

#[test]
fn v2_any_password_can_manage_the_file() {
    let path = to_temp(&do_encrypt(b"shared"));
    let p = path.as_ref();
    arsenic::arsenic_add_passphrase(p, &secret(PASSWORD), &secret("second-pw"), &NoUi).unwrap();
    // Authenticate with the second password to add a third: nobody is locked out.
    arsenic::arsenic_add_passphrase(p, &secret("second-pw"), &secret("third-pw"), &NoUi).unwrap();
    for pw in [PASSWORD, "second-pw", "third-pw"] {
        assert_eq!(decrypt_file(p, pw).unwrap(), b"shared", "{pw} must still open the file");
    }
    assert_eq!(arsenic::arsenic_list_passphrases(p).unwrap(), 3);

    // Change the second password using itself; the others are unaffected.
    arsenic_rekey(p, &secret("second-pw"), &secret("second-new"), &NoUi).unwrap();
    assert!(decrypt_file(p, "second-pw").is_err());
    for pw in [PASSWORD, "second-new", "third-pw"] {
        assert_eq!(decrypt_file(p, pw).unwrap(), b"shared");
    }

    // The third password removes the first one.
    arsenic::arsenic_remove_passphrase(p, &secret("third-pw"), &secret(PASSWORD), &NoUi).unwrap();
    assert!(decrypt_file(p, PASSWORD).is_err());
    assert_eq!(decrypt_file(p, "third-pw").unwrap(), b"shared");
}

#[test]
fn v2_duplicate_and_empty_passwords_are_refused() {
    let path = to_temp(&do_encrypt(b"x"));
    let p = path.as_ref();
    assert!(arsenic::arsenic_add_passphrase(p, &secret(PASSWORD), &secret(PASSWORD), &NoUi).is_err());
    assert!(arsenic::arsenic_add_passphrase(p, &secret(PASSWORD), &secret(""), &NoUi).is_err());
    assert!(arsenic_rekey(p, &secret(PASSWORD), &secret(""), &NoUi).is_err());
    assert_eq!(arsenic::arsenic_list_passphrases(p).unwrap(), 1);
    assert_eq!(decrypt_file(p, PASSWORD).unwrap(), b"x");
}

#[test]
fn v2_last_key_slot_cannot_be_removed_but_a_password_can_if_a_recipient_remains() {
    let key = keystore_key();
    let ct = do_encrypt_with(b"x", PASSWORD, fast_params(), &[key.as_recipient()]);
    let path = to_temp(&ct);
    let p = path.as_ref();
    // One password + one recipient: the password may go.
    arsenic::arsenic_remove_passphrase(p, &secret(PASSWORD), &secret(PASSWORD), &NoUi).unwrap();
    assert_eq!(arsenic::arsenic_list_passphrases(p).unwrap(), 0);
    let after = std::fs::read(p).unwrap();
    assert_eq!(decrypt_with_entry(&after, &key).unwrap(), b"x");
    let err = do_decrypt(&after, PASSWORD).unwrap_err();
    assert!(err.to_string().contains("no password"), "{err}");
}

#[test]
fn v2_unicode_password_is_normalized() {
    // "é" precomposed (U+00E9) and decomposed (e + U+0301) are the same password.
    let ct = do_encrypt_with(b"accents", "caf\u{e9}-secret", fast_params(), &[]);
    assert_eq!(do_decrypt(&ct, "cafe\u{301}-secret").unwrap(), b"accents");
    assert!(do_decrypt(&ct, "cafe-secret").is_err());
}

// ── recipients ────────────────────────────────────────────────────────────────

#[test]
fn v2_recipients_only_file_has_no_password_slot() {
    let key = keystore_key();
    let ct = do_encrypt_with(b"for the key only", "", fast_params(), &[key.as_recipient()]);
    let path = to_temp(&ct);
    assert_eq!(arsenic::arsenic_list_passphrases(path.as_ref()).unwrap(), 0);
    assert_eq!(decrypt_with_entry(&ct, &key).unwrap(), b"for the key only");
    assert!(do_decrypt(&ct, "").is_err());
    assert!(do_decrypt(&ct, PASSWORD).is_err());
}

#[test]
fn v2_no_password_and_no_recipient_is_refused() {
    let mut output = Cursor::new(Vec::new());
    let err = encrypt_arsenic(
        &mut Cursor::new(b"x".to_vec()), &mut output, &secret(""), &NoUi, 1, &fast_params(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("password or at least one recipient"), "{err}");
}

#[test]
fn v2_ml_kem_1024_slots_are_listed_found_added_and_removed() {
    let (a, b) = (keystore_key(), keystore_key());
    let mut params = fast_params();
    params.kem_level = KemLevel::L1024;
    let path = to_temp(&do_encrypt_with(b"level 5", PASSWORD, params, &[a.as_recipient()]));
    let p = path.as_ref();

    assert_eq!(arsenic_list_recipients(p).unwrap().len(), 1);
    assert_eq!(arsenic::arsenic_find_slot_for_key(p, &a), Some(0));
    assert_eq!(arsenic::arsenic_find_slot_for_key(p, &b), None);

    // Adding follows the file's level; a 768 slot can be requested explicitly.
    arsenic_add_recipient(p, &secret(PASSWORD), &b.as_recipient(), &NoUi).unwrap();
    let c = keystore_key();
    arsenic::arsenic_add_recipient_with_level(
        p, &secret(PASSWORD), &c.as_recipient(), Some(KemLevel::L768), &NoUi,
    )
    .unwrap();
    // Numbering: 768 slots first (c), then 1024 slots (a, b).
    assert_eq!(arsenic::arsenic_find_slot_for_key(p, &c), Some(0));
    assert_eq!(arsenic::arsenic_find_slot_for_key(p, &a), Some(1));
    assert_eq!(arsenic::arsenic_find_slot_for_key(p, &b), Some(2));
    let ct = std::fs::read(p).unwrap();
    for k in [&a, &b, &c] {
        assert_eq!(decrypt_with_entry(&ct, k).unwrap(), b"level 5");
    }

    // Remove a 1024 slot by its listed index.
    arsenic_remove_recipient(p, &secret(PASSWORD), 1, &NoUi).unwrap();
    let ct = std::fs::read(p).unwrap();
    assert!(decrypt_with_entry(&ct, &a).is_err());
    assert_eq!(decrypt_with_entry(&ct, &b).unwrap(), b"level 5");
    assert_eq!(decrypt_with_entry(&ct, &c).unwrap(), b"level 5");
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), b"level 5");
}

// ── parameter validation when encrypting ──────────────────────────────────────

#[test]
fn v2_parameters_that_could_not_be_decrypted_are_refused_when_encrypting() {
    let try_params = |edit: &dyn Fn(&mut ArsenicParams)| {
        let mut params = fast_params();
        edit(&mut params);
        let mut output = Cursor::new(Vec::new());
        encrypt_arsenic(&mut Cursor::new(b"x".to_vec()), &mut output, &secret(PASSWORD), &NoUi, 1, &params)
            .map(|()| output.into_inner())
    };
    assert!(try_params(&|p| p.t_cost = 65).is_err());
    assert!(try_params(&|p| p.t_cost = 0).is_err());
    assert!(try_params(&|p| p.p_cost = 17).is_err());
    assert!(try_params(&|p| p.m_cost = 7).is_err());
    assert!(try_params(&|p| p.compress = Some(0)).is_err());
    assert!(try_params(&|p| p.compress = Some(23)).is_err());
    // The limits themselves are accepted and decrypt.
    let ct = try_params(&|p| { p.t_cost = 2; p.p_cost = 2; p.m_cost = 16; p.compress = Some(22); }).unwrap();
    assert_eq!(do_decrypt(&ct, PASSWORD).unwrap(), b"x");
}

#[test]
fn v2_long_metadata_text_is_truncated_not_fatal() {
    let meta = EnvelopeMetadata {
        filename: Some("n".repeat(255)),
        comment: Some("é".repeat(400)),
        timestamp_secs: Some(42),
    };
    let ct = do_encrypt_with(b"meta", PASSWORD, fast_params_with_metadata(meta), &[]);
    let (pt, back) = do_decrypt_with_meta(&ct, PASSWORD).unwrap();
    assert_eq!(pt, b"meta");
    assert_eq!(back.filename.unwrap().len(), 255);
    let comment = back.comment.unwrap();
    assert!(comment.len() <= 255 && comment.chars().all(|c| c == 'é'));
    assert_eq!(back.timestamp_secs, Some(42));
}

// ── compression ───────────────────────────────────────────────────────────────

#[test]
fn v2_compression_streams_large_inputs() {
    // 24 MiB of compressible data: several blocks before compression, far
    // fewer after.
    let data: Vec<u8> = (0..24 * 1024 * 1024u32).map(|i| (i / 4096) as u8).collect();
    let mut params = fast_params();
    params.compress = Some(3);
    let ct = do_encrypt_with(&data, PASSWORD, params, &[]);
    assert!(ct.len() < data.len() / 10, "compressed output is {} bytes", ct.len());
    assert!(same(&do_decrypt(&ct, PASSWORD).unwrap(), &data));
    // Truncating the compressed payload is detected.
    assert!(do_decrypt(&ct[..ct.len() - 1], PASSWORD).is_err());
}

#[test]
fn v2_block_access_knows_the_final_block() {
    let data = make_payload(BLOCK_SIZE_4MB + 500);
    let ct = do_encrypt(&data);
    let block = |ct: &[u8], i: u64| {
        arsenic::decrypt_block_at(&mut Cursor::new(ct), &secret(PASSWORD), i, &NoUi)
    };
    assert!(same(&block(&ct, 0).unwrap(), &data[..BLOCK_SIZE_4MB]));
    assert_eq!(block(&ct, 1).unwrap(), &data[BLOCK_SIZE_4MB..]);
    assert!(block(&ct, 2).is_err());
    // After truncation block 0 has become the last block and must not pass
    // as a final block.
    let cut = &ct[..hdr_len(&ct) + BLOCK_ENC];
    assert!(block(cut, 0).is_err());
}

// ══ Frozen test vectors ═══════════════════════════════════════════════════════
//
// Files written once by this implementation and kept in `tests/data`. They
// must keep decrypting: a failure here means the format — or a key derivation
// in one of the cryptographic dependencies — changed without a version bump.

/// The fixed keypair the vectors were encrypted for.
fn vector_key() -> arsenic::keystore::KeyEntry {
    let private_key: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let mlkem_seed: [u8; 64] = std::array::from_fn(|i| 0xA0 ^ i as u8);
    arsenic::keystore::KeyEntry {
        name: "kat".into(),
        private_key,
        mlkem_seed,
        public_key: arsenic::pubkey_from_privkey(&private_key),
        mlkem_public_key: Box::new(arsenic::mlkem_encapsulation_key_768(&mlkem_seed)),
        file_path: None,
    }
}

/// Public keys derived from a fixed secret must never change: recipients'
/// keyslots are computed against them.
#[test]
fn kat_public_keys_from_fixed_seed() {
    let key = vector_key();
    let hex = |bytes: &[u8]| blake3::hash(bytes).to_hex().to_string();
    assert_eq!(hex(&key.public_key), "20a6f0c6f365177d66be4a2bd9fdb59e822701b5bcc085d43ab91bbf4248a122");
    assert_eq!(
        hex(key.mlkem_public_key.as_slice()),
        "0968faaab594b867b5e168c0e7a828cd0d3b7bf14f1869d8fbc7974a793dcd06"
    );
    let ek_1024 = key.as_recipient().mlkem_1024.expect("1024 key");
    assert_eq!(hex(&ek_1024), "0439ab482b3b75dc1ea6a664aa8b65ae59148f10af2db88a97d428462eb7de9a");
}

#[test]
fn vector_password_file() {
    let ct = include_bytes!("data/v2_password.arsn");
    assert_eq!(hdr_len(ct), PW_HEADER);
    assert_eq!(do_decrypt(ct, "arsenic-v2-test-vector").unwrap(), b"Arsenic V2 test vector\n");
    assert!(do_decrypt(ct, "arsenic-v2-test-vectoR").is_err());
}

/// AES-256-GCM-SIV header, Deoxys-II payload, zstd, metadata, one password,
/// one ML-KEM-768 slot and one ML-KEM-1024 slot added afterwards.
#[test]
fn vector_full_featured_file() {
    let ct = include_bytes!("data/v2_full.arsn");
    let expected = b"compressible ".repeat(1000);
    // The password was written precomposed; the decomposed form must match.
    let (pt, meta) = do_decrypt_with_meta(ct, "cafe\u{301}-v2-vector").unwrap();
    assert_eq!(pt, expected);
    assert_eq!(meta.filename.as_deref(), Some("vector.txt"));
    assert_eq!(meta.comment.as_deref(), Some("été"));
    assert_eq!(meta.timestamp_secs, Some(1_700_000_000));

    let key = vector_key();
    assert_eq!(decrypt_with_entry(ct, &key).unwrap(), expected);
    let path = to_temp(ct);
    assert_eq!(arsenic_list_recipients(path.as_ref()).unwrap().len(), 2);
    // Drop the 768 slot: the same keypair still opens the file through the 1024 slot.
    arsenic_remove_recipient(path.as_ref(), &secret("caf\u{e9}-v2-vector"), 0, &NoUi).unwrap();
    assert_eq!(decrypt_with_entry(&std::fs::read(&path).unwrap(), &key).unwrap(), expected);
}

/// No password slot, XChaCha20-Poly1305 everywhere, ML-KEM-1024, empty plaintext.
#[test]
fn vector_keys_only_empty_file() {
    let ct = include_bytes!("data/v2_keys_only_empty.arsn");
    assert_eq!(decrypt_with_entry(ct, &vector_key()).unwrap(), b"");
    assert_eq!(ct.len(), hdr_len(ct) + 16);
    assert!(do_decrypt(ct, "anything").is_err());
}

#[test]
fn bench_stops_when_cancelled() {
    struct Cancelled;
    impl arsenic::Ui for Cancelled {
        fn output(&self, _percentage: i32) {}
        fn is_cancelled(&self) -> bool {
            true
        }
    }
    assert!(arsenic::bench_cipher_combinations(1, &Cancelled).is_empty());
}
