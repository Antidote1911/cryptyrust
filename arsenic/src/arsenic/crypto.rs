use std::io::{Read, Seek, SeekFrom, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::fill as os_fill;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::errors::CoreErr;
use crate::secret::Secret;
use crate::Ui;

use super::cipher_dispatch;
use super::header::{
    build_envelope_region, build_header_bytes, compute_header_mac,
    deserialize_meta_tlv, parse_envelope, parse_header_bytes, serialize_meta_tlv,
    serialize_pre_mac, verify_header_mac,
    HybridKeyslot, HybridKeyslot1024, MlDsaSignature, EnvelopeContent, EnvelopeMetadata,
    ParsedEnvelope, PublicHeader, SenderInfo,
    ASYM_COUNT_LEN, ASYM_KEYSLOT_LEN, ASYM_1024_COUNT_LEN, ASYM_1024_KEYSLOT_LEN, GCM_TAG,
    MERKLE_V1, META_TLV_MANDATORY_PT_LEN, MIN_HEADER_TOTAL_SIZE, PUB_HEADER_LEN, WRAPPED_DEK_LEN,
    SIG_PRESENT_LEN, MLDSA_VERIFYING_KEY_LEN, MLDSA_SIGNATURE_LEN,
};
use super::hybrid_kem;
use super::{
    CipherId, HybridRecipient, KemLevel,
    BLOCK_ID_32MB, BLOCK_ID_4MB, BLOCK_SIZE_32MB, BLOCK_SIZE_4MB,
    LARGE_FILE_THRESHOLD, MAX_ARGON2_RAM_KB, MAX_HEADER_TOTAL_SIZE, MAX_T_COST, MAX_P_COST,
};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, Signer, Verifier, Keypair, Seed as MlDsaSeed};

// ── KDF parameter validation ──────────────────────────────────────────────────

/// Reject headers with KDF parameters outside safe bounds **before** running Argon2id.
///
/// This prevents a reverse-DoS where a tampered file declares absurdly expensive
/// parameters (e.g. t=1000, m=10 GiB) to waste the decryptor's resources.
/// The check is free (no KDF invocation) and rejects tampered files immediately.
fn validate_kdf_params(t_cost: u32, m_cost: u32, p_cost: u32) -> Result<(), CoreErr> {
    if t_cost == 0 || t_cost > MAX_T_COST {
        return Err(CoreErr::DecryptFail(format!(
            "t_cost {t_cost} out of range [1, {MAX_T_COST}]"
        )));
    }
    if m_cost < 8 || m_cost > MAX_ARGON2_RAM_KB {
        return Err(CoreErr::DecryptFail(format!(
            "m_cost {m_cost} KiB out of range [8, {MAX_ARGON2_RAM_KB}]"
        )));
    }
    if p_cost == 0 || p_cost > MAX_P_COST {
        return Err(CoreErr::DecryptFail(format!(
            "p_cost {p_cost} out of range [1, {MAX_P_COST}]"
        )));
    }
    Ok(())
}

// ── Domain AAD for envelope AEAD operations ───────────────────────────────────
// Binding a non-empty domain string as AAD provides explicit separation between
// the three distinct contexts in which envelope_encrypt/decrypt is called.

const AAD_SYM_WRAPPED_DEK:    &[u8] = b"arsenic-v1-wrapped-dek";
const AAD_HYBRID_WRAPPED_DEK: &[u8] = b"arsenic-v1-hybrid-wrapped-dek";
const AAD_PROTECTED_META:     &[u8] = b"arsenic-v1-protected-meta";

// ── OS random bytes ───────────────────────────────────────────────────────────

/// Fill a fixed-size array with bytes from the OS CSPRNG (no PRNG layer).
#[inline]
fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    os_fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

// ── Key / nonce derivation ────────────────────────────────────────────────────

fn derive_kek(
    password: &[u8],
    salt: &[u8; 16],
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
) -> Result<Secret<[u8; 32]>, CoreErr> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| CoreErr::Argon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CoreErr::Argon2Hash)?;
    Ok(Secret::new(key))
}

fn derive_block_key(dek: &[u8; 32], block_index: u64) -> [u8; 32] {
    *blake3::keyed_hash(dek, &block_index.to_le_bytes()).as_bytes()
}

fn derive_block_nonce(file_base_nonce: &[u8; 24], block_index: u64) -> [u8; 24] {
    let mut material = [0u8; 32];
    material[..24].copy_from_slice(file_base_nonce);
    material[24..].copy_from_slice(&block_index.to_le_bytes());
    let hash = blake3::derive_key("Arsenic V1 Block Nonce", &material);
    hash[..24].try_into().expect("24 <= 32")
}

fn derive_meta_key(dek: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("Arsenic V1 Metadata Key", dek)
}

fn derive_meta_nonce(dek: &[u8; 32]) -> [u8; 12] {
    let h = blake3::derive_key("Arsenic V1 Meta Nonce", dek);
    h[..12].try_into().expect("12 <= 32")
}

// ── Merkle v1 ─────────────────────────────────────────────────────────────────

fn merkle_leaf(data: &[u8]) -> [u8; 32] {
    blake3::derive_key("Arsenic V1 Merkle Leaf v1", data)
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    blake3::derive_key("Arsenic V1 Merkle Node v1", &buf)
}

fn merkle_root_v1(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let mut current = leaves.to_vec();
            while current.len() > 1 {
                let mut next = Vec::with_capacity(current.len().div_ceil(2));
                let mut i = 0;
                while i < current.len() {
                    if i + 1 < current.len() {
                        next.push(merkle_node(&current[i], &current[i + 1]));
                    } else {
                        next.push(current[i]);
                    }
                    i += 2;
                }
                current = next;
            }
            current[0]
        }
    }
}

// ── Block size selection ──────────────────────────────────────────────────────

fn select_block_params(filesize: u64) -> (usize, u8) {
    if filesize < LARGE_FILE_THRESHOLD {
        (BLOCK_SIZE_4MB, BLOCK_ID_4MB)
    } else {
        (BLOCK_SIZE_32MB, BLOCK_ID_32MB)
    }
}

fn block_size_from_id(id: u8) -> Result<usize, CoreErr> {
    match id {
        BLOCK_ID_4MB => Ok(BLOCK_SIZE_4MB),
        BLOCK_ID_32MB => Ok(BLOCK_SIZE_32MB),
        _ => Err(CoreErr::DecryptFail(format!(
            "Unknown block size ID: {id:#x}"
        ))),
    }
}

// ── Read helpers ──────────────────────────────────────────────────────────────

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut nread = 0;
    while nread < buf.len() {
        match reader.read(&mut buf[nread..])? {
            0 => break,
            n => nread += n,
        }
    }
    Ok(nread)
}

/// Read the full variable-length header (u32 header_total_size at offset 9).
fn read_header<R: Read>(input: &mut R) -> Result<Vec<u8>, CoreErr> {
    // Need 13 bytes to reach the end of the u32 header_total_size field.
    let mut prefix = [0u8; 13];
    input
        .read_exact(&mut prefix)
        .map_err(|_| CoreErr::BadSignature)?;

    let header_total_size =
        u32::from_le_bytes([prefix[9], prefix[10], prefix[11], prefix[12]]) as usize;

    if header_total_size < MIN_HEADER_TOTAL_SIZE
        || header_total_size > MAX_HEADER_TOTAL_SIZE as usize
    {
        return Err(CoreErr::DecryptFail(format!(
            "header_total_size {header_total_size} out of range [{MIN_HEADER_TOTAL_SIZE}, {}]",
            MAX_HEADER_TOTAL_SIZE
        )));
    }

    let mut header_buf = vec![0u8; header_total_size];
    header_buf[..13].copy_from_slice(&prefix);
    input
        .read_exact(&mut header_buf[13..])
        .map_err(|_| CoreErr::BadSignature)?;
    Ok(header_buf)
}

/// Read one encrypted block from the payload stream.
///
/// The block size is deterministic: `block_size + GCM_TAG` for all blocks
/// except the last one, which covers the remainder of `compressed_size`.
fn read_one_enc_block<R: Read>(
    input: &mut R,
    block_index: u64,
    num_blocks: u64,
    block_size: usize,
    compressed_size: u64,
) -> Result<Vec<u8>, CoreErr> {
    let is_last = block_index + 1 == num_blocks;
    let expected_enc_size = if is_last {
        let rem = compressed_size % block_size as u64;
        let last_pt = if rem == 0 { block_size } else { rem as usize };
        last_pt + GCM_TAG
    } else {
        block_size + GCM_TAG
    };
    let mut buf = vec![0u8; expected_enc_size];
    let n = read_full(input, &mut buf)?;
    if n < expected_enc_size {
        return Err(CoreErr::DecryptFail(format!(
            "truncated payload: block {block_index} expected {expected_enc_size} bytes, got {n}"
        )));
    }
    Ok(buf)
}

// ── Envelope size helpers ─────────────────────────────────────────────────────

fn metadata_extra_pt_len(meta: &EnvelopeMetadata) -> usize {
    let mut extra = 0usize;
    if let Some(ref s) = meta.filename {
        let n = s.len().min(255);
        if n > 0 {
            extra += 2 + n;
        }
    }
    if let Some(ref s) = meta.comment {
        let n = s.len().min(255);
        if n > 0 {
            extra += 2 + n;
        }
    }
    if meta.timestamp_secs.is_some() {
        extra += 2 + 8;
    }
    extra
}

// ── Hybrid keyslot helpers ────────────────────────────────────────────────────

/// Wrap `dek` for one hybrid (X25519 + ML-KEM-1024) recipient.
pub(crate) fn wrap_dek_hybrid_1024(
    hdr_cipher: CipherId,
    recipient: &HybridRecipient,
    dek: &[u8; 32],
) -> Result<HybridKeyslot1024, CoreErr> {
    use hybrid_kem::EK_LEN_1024;
    let ephemeral_bytes: [u8; 32] = random_array();
    let ephemeral_secret = X25519StaticSecret::from(ephemeral_bytes);
    let ephemeral_pk_x25519 = X25519PublicKey::from(&ephemeral_secret);
    let recipient_x25519_pk = X25519PublicKey::from(recipient.x25519);
    let ss_x25519 = ephemeral_secret.diffie_hellman(&recipient_x25519_pk);

    // The 1024 EK is stored in recipient.mlkem_1024 (1568 bytes).
    let ek_1024: [u8; EK_LEN_1024] = recipient.mlkem_1024.ok_or_else(|| {
        CoreErr::EncryptFail("Recipient has no ML-KEM-1024 key — use KemLevel::L1024 when generating".into())
    })?;
    let m: [u8; 32] = random_array();
    let (mlkem_ct, ss_mlkem) = hybrid_kem::encaps_1024(&ek_1024, &m);

    let wrapping_key = hybrid_wrapping_key_1024(
        ephemeral_pk_x25519.as_bytes(), &mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
    );

    let kek_nonce: [u8; 12] = random_array();
    let wrapped = cipher_dispatch::envelope_encrypt(hdr_cipher, &wrapping_key, &kek_nonce, AAD_HYBRID_WRAPPED_DEK, dek)?;
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(&wrapped);

    Ok(HybridKeyslot1024 {
        ephemeral_x25519: *ephemeral_pk_x25519.as_bytes(),
        mlkem_ct,
        kek_nonce,
        wrapped_dek,
    })
}

fn hybrid_wrapping_key_1024(
    eph_x25519_pk: &[u8; 32],
    mlkem_ct: &[u8; 1568],
    ss_x25519: &[u8; 32],
    ss_mlkem: &[u8; 32],
) -> [u8; 32] {
    let mut m = [0u8; 32 + 1568 + 32 + 32];
    let mut o = 0;
    m[o..o+32].copy_from_slice(eph_x25519_pk);   o += 32;
    m[o..o+1568].copy_from_slice(mlkem_ct);       o += 1568;
    m[o..o+32].copy_from_slice(ss_x25519);        o += 32;
    m[o..o+32].copy_from_slice(ss_mlkem);
    blake3::derive_key("Arsenic Hybrid KEM 1024", &m)
}

/// Wrap `dek` for one hybrid (X25519 + ML-KEM-768) recipient.
///
/// Hybrid wrapping key binds both shared secrets and all public values:
///   `BLAKE3_derive_key("Arsenic Hybrid KEM",
///      eph_x25519_pk || mlkem_ct || ss_x25519 || ss_mlkem)`
pub(crate) fn wrap_dek_hybrid(
    hdr_cipher: CipherId,
    recipient: &HybridRecipient,
    dek: &[u8; 32],
) -> Result<HybridKeyslot, CoreErr> {
    // X25519 half
    let ephemeral_bytes: [u8; 32] = random_array();
    let ephemeral_secret = X25519StaticSecret::from(ephemeral_bytes);
    let ephemeral_pk_x25519 = X25519PublicKey::from(&ephemeral_secret);
    let recipient_x25519_pk = X25519PublicKey::from(recipient.x25519);
    let ss_x25519 = ephemeral_secret.diffie_hellman(&recipient_x25519_pk);

    // ML-KEM-768 half
    let m: [u8; 32] = random_array();
    let (mlkem_ct, ss_mlkem) = hybrid_kem::encaps_768(&recipient.mlkem, &m);

    // Hybrid wrapping key
    let wrapping_key = hybrid_wrapping_key(
        ephemeral_pk_x25519.as_bytes(), &mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
    );

    let kek_nonce: [u8; 12] = random_array();
    let wrapped = cipher_dispatch::envelope_encrypt(hdr_cipher, &wrapping_key, &kek_nonce, AAD_HYBRID_WRAPPED_DEK, dek)?;
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(&wrapped);

    Ok(HybridKeyslot {
        ephemeral_x25519: *ephemeral_pk_x25519.as_bytes(),
        mlkem_ct,
        kek_nonce,
        wrapped_dek,
    })
}

/// Find which hybrid keyslot (by slot index) can be opened with this keypair.
///
/// Returns the **slot position** in the file's keyslot array, or `None`.
/// No symmetric password required — authentication is via ECDH + ML-KEM.
pub fn find_slot_for_privkey<R: Read>(
    input: &mut R,
    x25519_privkey: &[u8; 32],
    mlkem_seed: &[u8; 64],
) -> Result<Option<usize>, CoreErr> {
    let header_buf = read_header(input)?;
    let (pub_hdr, _, _, enc_env_region) = parse_header_bytes(&header_buf)?;
    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let envelope = parse_envelope(&enc_env_region)?;

    if envelope.hybrid_keyslots.is_empty() {
        return Ok(None);
    }

    let x25519_secret = X25519StaticSecret::from(*x25519_privkey);
    for (slot_idx, slot) in envelope.hybrid_keyslots.iter().enumerate() {
        let eph_pk = X25519PublicKey::from(slot.ephemeral_x25519);
        let ss_x25519 = x25519_secret.diffie_hellman(&eph_pk);
        let ss_mlkem = hybrid_kem::decaps_768(mlkem_seed, &slot.mlkem_ct);
        let wrapping_key = hybrid_wrapping_key(
            &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
        );
        if cipher_dispatch::envelope_decrypt(
            hdr_cipher, &wrapping_key, &slot.kek_nonce, AAD_HYBRID_WRAPPED_DEK, &slot.wrapped_dek,
        ).is_ok() {
            return Ok(Some(slot_idx));
        }
    }
    // Also try 1024 keyslots (offset by 768 count so indices don't collide).
    let offset = envelope.hybrid_keyslots.len();
    for (slot_idx, slot) in envelope.hybrid_keyslots_1024.iter().enumerate() {
        let eph_pk = X25519PublicKey::from(slot.ephemeral_x25519);
        let ss_x25519 = x25519_secret.diffie_hellman(&eph_pk);
        let ss_mlkem = hybrid_kem::decaps_1024(mlkem_seed, &slot.mlkem_ct);
        let wrapping_key = hybrid_wrapping_key_1024(
            &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
        );
        if cipher_dispatch::envelope_decrypt(
            hdr_cipher, &wrapping_key, &slot.kek_nonce, AAD_HYBRID_WRAPPED_DEK, &slot.wrapped_dek,
        ).is_ok() {
            return Ok(Some(offset + slot_idx));
        }
    }
    Ok(None)
}

/// A hybrid private keypair: X25519 key + independent ML-KEM seed.
pub struct HybridPrivKey<'a> {
    pub x25519_sk:  &'a [u8; 32],
    pub mlkem_seed: &'a [u8; 64],
}

/// Probe the header to find which keypair (if any) can open it.
/// Returns the index into `keys` that matches a keyslot.
pub fn find_decrypting_key<R: Read>(
    input: &mut R,
    keys: &[HybridPrivKey<'_>],
) -> Result<Option<usize>, CoreErr> {
    if keys.is_empty() {
        return Ok(None);
    }
    let header_buf = read_header(input)?;
    let (pub_hdr, _, _, enc_env_region) = parse_header_bytes(&header_buf)?;
    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let envelope = parse_envelope(&enc_env_region)?;
    if envelope.hybrid_keyslots.is_empty() && envelope.hybrid_keyslots_1024.is_empty() {
        return Ok(None);
    }
    for (i, key) in keys.iter().enumerate() {
        if unwrap_dek_hybrid(hdr_cipher, key.x25519_sk, key.mlkem_seed, &envelope.hybrid_keyslots).is_ok()
            || unwrap_dek_hybrid_1024(hdr_cipher, key.x25519_sk, key.mlkem_seed, &envelope.hybrid_keyslots_1024).is_ok()
        {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Try each hybrid keyslot (768 then 1024) with the given keypair until one yields the DEK.
pub(crate) fn unwrap_dek_hybrid(
    hdr_cipher: CipherId,
    x25519_privkey: &[u8; 32],
    mlkem_seed: &[u8; 64],
    hybrid_keyslots: &[HybridKeyslot],
) -> Result<[u8; 32], CoreErr> {
    let x25519_secret = X25519StaticSecret::from(*x25519_privkey);

    for slot in hybrid_keyslots {
        let eph_pk = X25519PublicKey::from(slot.ephemeral_x25519);
        let ss_x25519 = x25519_secret.diffie_hellman(&eph_pk);
        let ss_mlkem = hybrid_kem::decaps_768(mlkem_seed, &slot.mlkem_ct);
        let wrapping_key = hybrid_wrapping_key(
            &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
        );
        match cipher_dispatch::envelope_decrypt(
            hdr_cipher, &wrapping_key, &slot.kek_nonce, AAD_HYBRID_WRAPPED_DEK, &slot.wrapped_dek,
        ) {
            Ok(dek_vec) if dek_vec.len() == 32 => {
                let mut dek = [0u8; 32];
                dek.copy_from_slice(&dek_vec);
                return Ok(dek);
            }
            _ => continue,
        }
    }
    Err(CoreErr::NoAsymKeyFound)
}

/// Try each ML-KEM-1024 hybrid keyslot with the given keypair.
pub(crate) fn unwrap_dek_hybrid_1024(
    hdr_cipher: CipherId,
    x25519_privkey: &[u8; 32],
    mlkem_seed: &[u8; 64],
    keyslots_1024: &[HybridKeyslot1024],
) -> Result<[u8; 32], CoreErr> {
    let x25519_secret = X25519StaticSecret::from(*x25519_privkey);

    for slot in keyslots_1024 {
        let eph_pk = X25519PublicKey::from(slot.ephemeral_x25519);
        let ss_x25519 = x25519_secret.diffie_hellman(&eph_pk);
        let ss_mlkem = hybrid_kem::decaps_1024(mlkem_seed, &slot.mlkem_ct);
        let wrapping_key = hybrid_wrapping_key_1024(
            &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &ss_mlkem,
        );
        match cipher_dispatch::envelope_decrypt(
            hdr_cipher, &wrapping_key, &slot.kek_nonce, AAD_HYBRID_WRAPPED_DEK, &slot.wrapped_dek,
        ) {
            Ok(dek_vec) if dek_vec.len() == 32 => {
                let mut dek = [0u8; 32];
                dek.copy_from_slice(&dek_vec);
                return Ok(dek);
            }
            _ => continue,
        }
    }
    Err(CoreErr::NoAsymKeyFound)
}

/// BLAKE3 hybrid KEM binding function.
fn hybrid_wrapping_key(
    eph_x25519_pk: &[u8; 32],
    mlkem_ct: &[u8; 1088],
    ss_x25519: &[u8; 32],
    ss_mlkem: &[u8; 32],
) -> [u8; 32] {
    let mut m = [0u8; 32 + 1088 + 32 + 32];
    let mut o = 0;
    m[o..o+32].copy_from_slice(eph_x25519_pk);   o += 32;
    m[o..o+1088].copy_from_slice(mlkem_ct);       o += 1088;
    m[o..o+32].copy_from_slice(ss_x25519);        o += 32;
    m[o..o+32].copy_from_slice(ss_mlkem);
    blake3::derive_key("Arsenic Hybrid KEM", &m)
}

// ── Envelope decryption (symmetric path) ─────────────────────────────────────

fn decrypt_envelope_symmetric(
    hdr_cipher: CipherId,
    kek: &[u8; 32],
    kek_nonce: &[u8; 12],
    envelope: &ParsedEnvelope,
) -> Result<EnvelopeContent, CoreErr> {
    let dek_vec = cipher_dispatch::envelope_decrypt(
        hdr_cipher,
        kek,
        kek_nonce,
        AAD_SYM_WRAPPED_DEK,
        &envelope.wrapped_dek,
    )?;
    if dek_vec.len() != 32 {
        return Err(CoreErr::DecryptFail(
            "WrappedDEK plaintext must be 32 bytes".into(),
        ));
    }
    let dek: [u8; 32] = dek_vec.try_into().unwrap();
    decrypt_protected_meta(hdr_cipher, dek, &envelope.protected_meta)
}

fn decrypt_protected_meta(
    hdr_cipher: CipherId,
    dek: [u8; 32],
    protected_meta: &[u8],
) -> Result<EnvelopeContent, CoreErr> {
    let meta_key = derive_meta_key(&dek);
    let meta_nonce = derive_meta_nonce(&dek);
    let meta_pt =
        cipher_dispatch::envelope_decrypt(hdr_cipher, &meta_key, &meta_nonce, AAD_PROTECTED_META, protected_meta)?;
    deserialize_meta_tlv(&meta_pt, dek)
}

// ── Public encrypt ────────────────────────────────────────────────────────────

/// Encrypt a file in the Arsenic format (streaming, one block at a time).
///
/// Memory: O(block_size + N_blocks × 32).
/// The Argon2id KDF runs **after** all payload blocks are written (the header
/// placeholder is sealed at the very end via a single Seek to offset 0).
pub fn encrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
    params: &super::ArsenicParams,
) -> Result<(), CoreErr>
where
    R: Read,
    W: Write + Seek,
{
    let salt: [u8; 16] = random_array();
    let file_base_nonce: [u8; 24] = random_array();
    let kek_nonce: [u8; 12] = random_array();
    let mut dek: [u8; 32] = random_array();

    let (block_size, block_size_id) = select_block_params(filesize);
    let pld_cipher = params.pld_cipher;

    let meta = &params.metadata;
    let meta_pt_len = META_TLV_MANDATORY_PT_LEN + metadata_extra_pt_len(meta);
    let protected_meta_enc_len = meta_pt_len + GCM_TAG;

    // Split recipients into 768 and 1024 depending on kem_level.
    let (recipients_768, recipients_1024) = match params.kem_level {
        KemLevel::L768  => (params.recipients.as_slice(), [].as_slice()),
        KemLevel::L1024 => ([].as_slice(), params.recipients.as_slice()),
    };

    let sig_region_len = if params.signing_key.is_some() {
        SIG_PRESENT_LEN + MLDSA_VERIFYING_KEY_LEN + MLDSA_SIGNATURE_LEN
    } else {
        SIG_PRESENT_LEN
    };

    let sender_info: Option<SenderInfo> = match (&params.sender_name, &params.sender_x25519_pk, &params.sender_mlkem_pk) {
        (Some(name), Some(x25519), Some(mlkem)) => Some(SenderInfo {
            name: name.clone(),
            x25519_pk: *x25519,
            mlkem_pk: *mlkem,
        }),
        _ => None,
    };
    let sender_region_len = match &sender_info {
        Some(s) => s.name.as_bytes().len().min(255) + 2 + 32 + 1184 + 1,
        None => 1,
    };

    let header_total_size = PUB_HEADER_LEN
        + WRAPPED_DEK_LEN
        + ASYM_COUNT_LEN + recipients_768.len() * ASYM_KEYSLOT_LEN
        + ASYM_1024_COUNT_LEN + recipients_1024.len() * ASYM_1024_KEYSLOT_LEN
        + protected_meta_enc_len
        + sig_region_len
        + sender_region_len;
    if header_total_size > MAX_HEADER_TOTAL_SIZE as usize {
        return Err(CoreErr::EncryptFail("Header too large (too many recipients or metadata)".into()));
    }

    // Write a zero-filled placeholder; the real header is sealed after the
    // payload is fully written and the Merkle root is known.
    output.write_all(&vec![0u8; header_total_size])?;

    // ── Stream blocks one at a time ───────────────────────────────────────
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut total_read: u64 = 0;
    let mut block_index: u64 = 0;
    {
        let mut buf = vec![0u8; block_size];
        loop {
            let n = read_full(input, &mut buf)?;
            if n == 0 {
                break;
            }
            total_read += n as u64;

            if ui.is_cancelled() {
                return Err(CoreErr::Cancelled);
            }

            let block_nonce = derive_block_nonce(&file_base_nonce, block_index);
            let block_key = derive_block_key(&dek, block_index);
            let aad = block_index.to_le_bytes();

            let encrypted = cipher_dispatch::block_encrypt(
                pld_cipher, &block_key, &block_nonce, &aad, &buf[..n],
            )?;

            leaves.push(merkle_leaf(&encrypted));
            output.write_all(&encrypted)?;

            let pct = if filesize > 0 {
                ((total_read as f32 / filesize as f32) * 95.0) as i32
            } else {
                50
            };
            ui.output(pct.min(95));

            if n < block_size {
                break;
            }
            block_index += 1;
        }
    }

    let root = merkle_root_v1(&leaves);

    let env = EnvelopeContent {
        dek,
        merkle_root: root,
        original_size: total_read,
        block_size_id,
        merkle_algo_id: MERKLE_V1,
        filename: meta.filename.clone(),
        comment: meta.comment.clone(),
        timestamp_secs: meta.timestamp_secs,
    };
    let meta_tlv = serialize_meta_tlv(&env);

    let kek = derive_kek(
        password.expose().as_bytes(),
        &salt,
        params.t_cost,
        params.m_cost,
        params.p_cost,
    )?;

    let wrapped_dek_vec =
        cipher_dispatch::envelope_encrypt(params.hdr_cipher, kek.expose(), &kek_nonce, AAD_SYM_WRAPPED_DEK, &dek)?;
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(&wrapped_dek_vec);

    // ML-KEM-768 keyslots
    let mut hybrid_keyslots: Vec<HybridKeyslot> = Vec::with_capacity(recipients_768.len());
    for recipient in recipients_768 {
        hybrid_keyslots.push(wrap_dek_hybrid(params.hdr_cipher, recipient, &dek)?);
    }

    // ML-KEM-1024 keyslots
    let mut hybrid_keyslots_1024: Vec<HybridKeyslot1024> = Vec::with_capacity(recipients_1024.len());
    for recipient in recipients_1024 {
        hybrid_keyslots_1024.push(wrap_dek_hybrid_1024(params.hdr_cipher, recipient, &dek)?);
    }

    let meta_key = derive_meta_key(&dek);
    let meta_nonce = derive_meta_nonce(&dek);
    let protected_meta =
        cipher_dispatch::envelope_encrypt(params.hdr_cipher, &meta_key, &meta_nonce, AAD_PROTECTED_META, &meta_tlv)?;

    let pub_header = PublicHeader {
        header_total_size: header_total_size as u32,
        salt,
        t_cost: params.t_cost,
        m_cost: params.m_cost,
        p_cost: params.p_cost,
        file_base_nonce,
        kek_nonce,
        hdr_cipher_id: params.hdr_cipher.to_byte(),
        pld_cipher_id: params.pld_cipher.to_byte(),
    };

    let pre_mac_bytes = serialize_pre_mac(&pub_header);

    // Optional ML-DSA-65 signature over the public header parameters.
    let mldsa_sig = if let Some(seed) = params.signing_key {
        let seed_common: MlDsaSeed = seed.into();
        let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed_common);
        let vk = sk.verifying_key(); // via Keypair trait
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(pre_mac_bytes.as_slice());
        let vk_enc = vk.encode();
        let sig_enc = sig.encode();
        let mut vk_arr = [0u8; MLDSA_VERIFYING_KEY_LEN];
        vk_arr.copy_from_slice(vk_enc.as_slice());
        let mut sig_arr = [0u8; MLDSA_SIGNATURE_LEN];
        sig_arr.copy_from_slice(sig_enc.as_slice());
        Some(MlDsaSignature {
            verifying_key: Box::new(vk_arr),
            signature: Box::new(sig_arr),
        })
    } else {
        None
    };

    let enc_envelope = build_envelope_region(
        &wrapped_dek, &hybrid_keyslots, &hybrid_keyslots_1024, &protected_meta, mldsa_sig.as_ref(), sender_info.as_ref(),
    );

    let mac = compute_header_mac(kek.expose(), &pre_mac_bytes);
    let header_bytes = build_header_bytes(&pub_header, &mac, &enc_envelope);

    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header_bytes)?;
    output.flush()?;

    dek.zeroize();
    ui.output(100);
    Ok(())
}

// ── Public decrypt (symmetric password) ──────────────────────────────────────

/// Decrypt an Arsenic file using the symmetric password path.
///
/// **Two-pass, sliding-window parallel.**
///
/// Pass 1 (sequential): reads every encrypted block, computes its BLAKE3 leaf,
///   verifies the Merkle root.  No plaintext is written until verification passes.
///
/// Pass 2 (parallel windows): seeks back to the payload, reads blocks in
///   windows of `rayon::current_num_threads()`, AEAD-decrypts each window in
///   parallel, writes plaintext sequentially.
///
/// Memory: O(window_size × block_size + N_blocks × 32).
pub fn decrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
) -> Result<EnvelopeMetadata, CoreErr>
where
    R: Read + Seek,
    W: Write,
{
    if filesize < MIN_HEADER_TOTAL_SIZE as u64 {
        return Err(CoreErr::BadSignature);
    }

    let header_buf = read_header(input)?;
    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;

    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let pld_cipher = CipherId::from_byte(pub_hdr.pld_cipher_id)?;

    if pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Header size exceeds limit".into()));
    }
    validate_kdf_params(pub_hdr.t_cost, pub_hdr.m_cost, pub_hdr.p_cost)?;

    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    if !verify_header_mac(kek.expose(), &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let envelope = parse_envelope(&enc_env_region)?;

    // Verify ML-DSA signature if present.
    if let Some(ref mldsa) = envelope.mldsa_sig {
        let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(mldsa.verifying_key.as_slice())
            .map_err(|_| CoreErr::DecryptFail("Malformed ML-DSA verifying key".into()))?;
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_enc);
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(mldsa.signature.as_slice())
            .map_err(|_| CoreErr::DecryptFail("Malformed ML-DSA signature".into()))?;
        vk.verify(pre_mac_bytes.as_slice(), &sig)
            .map_err(|_| CoreErr::DecryptFail("ML-DSA signature verification failed — file may be forged".into()))?;
    }

    let env =
        decrypt_envelope_symmetric(hdr_cipher, kek.expose(), &pub_hdr.kek_nonce, &envelope)?;

    let block_size = block_size_from_id(env.block_size_id)?;
    let dek = env.dek;
    let file_base_nonce = pub_hdr.file_base_nonce;
    let num_blocks = env.original_size.div_ceil(block_size as u64);
    let payload_start = pub_hdr.header_total_size as u64;

    // ── Pass 1: verify Merkle root ────────────────────────────────────────
    // Only BLAKE3 hashing — no AEAD decryption, no plaintext written.
    // Memory: N_blocks × 32 bytes (≈ 2 MiB for 2 TiB / 32 MiB blocks).
    input.seek(SeekFrom::Start(payload_start))?;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_blocks as usize);
    for block_index in 0..num_blocks {
        let enc_block = read_one_enc_block(
            input, block_index, num_blocks, block_size, env.original_size,
        )?;
        leaves.push(merkle_leaf(&enc_block));
    }

    let computed_root = merkle_root_v1(&leaves);
    if computed_root != env.merkle_root {
        return Err(CoreErr::DecryptFail("Merkle root mismatch".into()));
    }

    // ── Pass 2: decrypt and write plaintext ───────────────────────────────
    input.seek(SeekFrom::Start(payload_start))?;
    for block_index in 0..num_blocks {
        if ui.is_cancelled() {
            return Err(CoreErr::Cancelled);
        }
        let enc_block = read_one_enc_block(
            input, block_index, num_blocks, block_size, env.original_size,
        )?;
        let block_key = derive_block_key(&dek, block_index);
        let block_nonce = derive_block_nonce(&file_base_nonce, block_index);
        let aad = block_index.to_le_bytes();
        let plaintext = cipher_dispatch::block_decrypt(
            pld_cipher, &block_key, &block_nonce, &aad, &enc_block,
        )?;
        output.write_all(&plaintext)?;
        let pct = (((block_index + 1) as f32 / num_blocks.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    output.flush()?;
    ui.output(100);
    Ok(env.metadata())
}

// ── Public decrypt (asymmetric X25519 private key) ────────────────────────────

/// Decrypt using a hybrid keypair (X25519 + independent ML-KEM seed).
///
/// Tries every asymmetric keyslot; returns `Err(NoAsymKeyFound)` if none matches.
/// Same two-pass streaming strategy as `decrypt_arsenic`.
pub fn decrypt_arsenic_with_key<R, W>(
    input: &mut R,
    output: &mut W,
    x25519_privkey: &Secret<[u8; 32]>,
    mlkem_seed: &[u8; 64],
    ui: &dyn Ui,
    filesize: u64,
) -> Result<EnvelopeMetadata, CoreErr>
where
    R: Read + Seek,
    W: Write,
{
    if filesize < MIN_HEADER_TOTAL_SIZE as u64 {
        return Err(CoreErr::BadSignature);
    }

    let header_buf = read_header(input)?;
    let (pub_hdr, _pre_mac_bytes, _stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;

    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let pld_cipher = CipherId::from_byte(pub_hdr.pld_cipher_id)?;

    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Parameters exceed safety limits".into()));
    }

    let envelope = parse_envelope(&enc_env_region)?;
    // Try 768 keyslots first, then 1024.
    let dek = unwrap_dek_hybrid(hdr_cipher, x25519_privkey.expose(), mlkem_seed, &envelope.hybrid_keyslots)
        .or_else(|_| unwrap_dek_hybrid_1024(hdr_cipher, x25519_privkey.expose(), mlkem_seed, &envelope.hybrid_keyslots_1024))?;
    let env = decrypt_protected_meta(hdr_cipher, dek, &envelope.protected_meta)?;

    let block_size = block_size_from_id(env.block_size_id)?;
    let file_base_nonce = pub_hdr.file_base_nonce;
    let num_blocks = env.original_size.div_ceil(block_size as u64);
    let payload_start = pub_hdr.header_total_size as u64;

    // ── Pass 1: verify Merkle root ────────────────────────────────────────
    input.seek(SeekFrom::Start(payload_start))?;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_blocks as usize);
    for block_index in 0..num_blocks {
        let enc_block = read_one_enc_block(
            input, block_index, num_blocks, block_size, env.original_size,
        )?;
        leaves.push(merkle_leaf(&enc_block));
    }

    let computed_root = merkle_root_v1(&leaves);
    if computed_root != env.merkle_root {
        return Err(CoreErr::DecryptFail("Merkle root mismatch".into()));
    }

    // ── Pass 2: decrypt and write plaintext ───────────────────────────────
    input.seek(SeekFrom::Start(payload_start))?;
    for block_index in 0..num_blocks {
        if ui.is_cancelled() {
            return Err(CoreErr::Cancelled);
        }
        let enc_block = read_one_enc_block(
            input, block_index, num_blocks, block_size, env.original_size,
        )?;
        let block_key = derive_block_key(&dek, block_index);
        let block_nonce = derive_block_nonce(&file_base_nonce, block_index);
        let aad = block_index.to_le_bytes();
        let plaintext = cipher_dispatch::block_decrypt(
            pld_cipher, &block_key, &block_nonce, &aad, &enc_block,
        )?;
        output.write_all(&plaintext)?;
        let pct = (((block_index + 1) as f32 / num_blocks.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    output.flush()?;
    ui.output(100);
    Ok(env.metadata())
}

// ── Public rekey ──────────────────────────────────────────────────────────────

/// Change the symmetric password without touching payload or asymmetric keyslots.
///
/// Only the 48-byte symmetric WrappedDEK is re-encrypted.  The asymmetric
/// keyslots and ProtectedMetadata bytes are copied unchanged.
pub fn rekey_arsenic<F>(
    file: &mut F,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr>
where
    F: Read + Write + Seek,
{
    ui.output(0);

    file.seek(SeekFrom::Start(0))?;
    let header_buf = read_header(file)?;

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;
    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;

    if pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Header size exceeds limit".into()));
    }
    validate_kdf_params(pub_hdr.t_cost, pub_hdr.m_cost, pub_hdr.p_cost)?;

    let kek_old = derive_kek(
        old_password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    if !verify_header_mac(kek_old.expose(), &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let new_salt: [u8; 16] = random_array();
    let new_kek_nonce: [u8; 12] = random_array();
    let kek_new = derive_kek(
        new_password.expose().as_bytes(),
        &new_salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;

    // Parse envelope to get symmetric WrappedDEK, preserving asym keyslots and ProtectedMetadata.
    let envelope = parse_envelope(&enc_env_region)?;

    let mut dek_vec = cipher_dispatch::envelope_decrypt(
        hdr_cipher,
        kek_old.expose(),
        &pub_hdr.kek_nonce,
        AAD_SYM_WRAPPED_DEK,
        &envelope.wrapped_dek,
    )?;

    let new_wrapped_dek_vec = cipher_dispatch::envelope_encrypt(
        hdr_cipher,
        kek_new.expose(),
        &new_kek_nonce,
        AAD_SYM_WRAPPED_DEK,
        &dek_vec,
    )?;
    dek_vec.zeroize();

    let mut new_wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    new_wrapped_dek.copy_from_slice(&new_wrapped_dek_vec);

    // Preserve all asymmetric keyslots, ProtectedMetadata, and sender region unchanged.
    let new_enc_envelope =
        build_envelope_region(&new_wrapped_dek, &envelope.hybrid_keyslots, &envelope.hybrid_keyslots_1024, &envelope.protected_meta, envelope.mldsa_sig.as_ref(), envelope.sender.as_ref());

    let new_pub_hdr = PublicHeader {

        header_total_size: pub_hdr.header_total_size,
        salt: new_salt,
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
        file_base_nonce: pub_hdr.file_base_nonce,
        kek_nonce: new_kek_nonce,
        hdr_cipher_id: pub_hdr.hdr_cipher_id,
        pld_cipher_id: pub_hdr.pld_cipher_id,
    };
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(kek_new.expose(), &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &new_enc_envelope);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&new_header)?;
    file.flush()?;

    ui.output(100);
    Ok(())
}

// ── In-file recipient management ──────────────────────────────────────────────

/// Return the ephemeral public keys of all asymmetric keyslots stored in the
/// header.  These identify keyslots but are NOT the recipients' own public keys.
pub fn list_recipients<R: Read>(input: &mut R) -> Result<Vec<[u8; 32]>, CoreErr> {
    let header_buf = read_header(input)?;
    let (_, _, _, enc_env_region) = parse_header_bytes(&header_buf)?;
    let envelope = parse_envelope(&enc_env_region)?;
    Ok(envelope
        .hybrid_keyslots
        .iter()
        .map(|s| s.ephemeral_x25519)
        .collect())
}

/// Build an updated header with a new asymmetric keyslot added.
///
/// Returns `(new_header_bytes, old_header_size)` so the caller can stream the
/// existing payload after the new header.
pub fn build_header_with_added_recipient<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
    hdr_cipher: CipherId,
    recipient: &HybridRecipient,
) -> Result<(Vec<u8>, usize), CoreErr> {
    file.seek(SeekFrom::Start(0))?;
    let header_buf = read_header(file)?;
    let old_header_size = header_buf.len();

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;

    if pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Header size exceeds limit".into()));
    }
    validate_kdf_params(pub_hdr.t_cost, pub_hdr.m_cost, pub_hdr.p_cost)?;

    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    if !verify_header_mac(kek.expose(), &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let envelope = parse_envelope(&enc_env_region)?;

    let mut dek_vec = cipher_dispatch::envelope_decrypt(
        hdr_cipher,
        kek.expose(),
        &pub_hdr.kek_nonce,
        AAD_SYM_WRAPPED_DEK,
        &envelope.wrapped_dek,
    )?;
    if dek_vec.len() != 32 {
        return Err(CoreErr::DecryptFail("WrappedDEK plaintext must be 32 bytes".into()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);
    dek_vec.zeroize();

    let new_slot = wrap_dek_hybrid(hdr_cipher, recipient, &dek)?;
    dek.zeroize();

    let mut new_asym = envelope.hybrid_keyslots;
    new_asym.push(new_slot);

    let new_enc_envelope =
        build_envelope_region(&envelope.wrapped_dek, &new_asym, &envelope.hybrid_keyslots_1024, &envelope.protected_meta, envelope.mldsa_sig.as_ref(), envelope.sender.as_ref());
    let new_header_size = PUB_HEADER_LEN + new_enc_envelope.len();

    if new_header_size > MAX_HEADER_TOTAL_SIZE as usize {
        return Err(CoreErr::EncryptFail("Too many recipients: header exceeds size limit".into()));
    }

    let new_pub_hdr = PublicHeader {
        header_total_size: new_header_size as u32,
        salt: pub_hdr.salt,
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
        file_base_nonce: pub_hdr.file_base_nonce,
        kek_nonce: pub_hdr.kek_nonce,
        hdr_cipher_id: pub_hdr.hdr_cipher_id,
        pld_cipher_id: pub_hdr.pld_cipher_id,
    };
    // Recompute MAC with KEK: header_total_size changed.
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(kek.expose(), &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &new_enc_envelope);

    Ok((new_header, old_header_size))
}

/// Build an updated header with the asymmetric keyslot at `index` removed.
///
/// Returns `(new_header_bytes, old_header_size)`.
pub fn build_header_with_removed_recipient<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
    index: usize,
) -> Result<(Vec<u8>, usize), CoreErr> {
    file.seek(SeekFrom::Start(0))?;
    let header_buf = read_header(file)?;
    let old_header_size = header_buf.len();

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;

    if pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Header size exceeds limit".into()));
    }
    validate_kdf_params(pub_hdr.t_cost, pub_hdr.m_cost, pub_hdr.p_cost)?;

    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    if !verify_header_mac(kek.expose(), &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let envelope = parse_envelope(&enc_env_region)?;

    if index >= envelope.hybrid_keyslots.len() {
        return Err(CoreErr::DecryptFail(format!(
            "Recipient index {index} out of range (file has {} asymmetric keyslots)",
            envelope.hybrid_keyslots.len()
        )));
    }

    let mut new_asym = envelope.hybrid_keyslots;
    new_asym.remove(index);

    let new_enc_envelope =
        build_envelope_region(&envelope.wrapped_dek, &new_asym, &envelope.hybrid_keyslots_1024, &envelope.protected_meta, envelope.mldsa_sig.as_ref(), envelope.sender.as_ref());
    let new_header_size = PUB_HEADER_LEN + new_enc_envelope.len();

    let new_pub_hdr = PublicHeader {
        header_total_size: new_header_size as u32,
        salt: pub_hdr.salt,
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
        file_base_nonce: pub_hdr.file_base_nonce,
        kek_nonce: pub_hdr.kek_nonce,
        hdr_cipher_id: pub_hdr.hdr_cipher_id,
        pld_cipher_id: pub_hdr.pld_cipher_id,
    };
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(kek.expose(), &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &new_enc_envelope);

    Ok((new_header, old_header_size))
}
