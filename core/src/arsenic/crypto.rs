use std::io::{Read, Seek, SeekFrom, Write};

use aead::{Aead, KeyInit, Payload};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::random;
use zeroize::Zeroize;

use crate::errors::CoreErr;
use crate::secret::Secret;
use crate::Ui;

use super::header::{
    build_header_bytes, compute_header_mac, compute_prekey, deserialize_envelope,
    parse_header_bytes, serialize_envelope, serialize_pre_mac, verify_header_mac, EnvelopeContent,
    PublicHeader, COMPRESS_NONE, DEFAULT_HEADER_SIZE, ENVELOPE_PT_LEN, GCM_TAG, TOTAL_HEADER_LEN,
};
use super::serpent_gcm::SerpentGcm;
use super::{
    BLOCK_ID_32MB, BLOCK_ID_4MB, BLOCK_SIZE_32MB, BLOCK_SIZE_4MB, LARGE_FILE_THRESHOLD,
    MAX_ARGON2_RAM_KB, MAX_HEADER_TOTAL_SIZE,
};

// ── Key / nonce derivation ────────────────────────────────────────────────

/// Derive KEK = Argon2id(password, salt, t_cost, m_cost, p_cost) → 32 bytes.
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

/// BlockKey_N = BLAKE3_keyed_hash(DEK, u64_le(N)) → 32 bytes.
fn derive_block_key(dek: &[u8; 32], block_index: u64) -> [u8; 32] {
    *blake3::keyed_hash(dek, &block_index.to_le_bytes()).as_bytes()
}

/// Nonce_N = BLAKE3_derive_key("Arsenic V2 Block Nonce", file_base_nonce || u64_le(N))[..24].
fn derive_block_nonce(file_base_nonce: &[u8; 24], block_index: u64) -> [u8; 24] {
    let mut material = [0u8; 32]; // 24 + 8
    material[..24].copy_from_slice(file_base_nonce);
    material[24..].copy_from_slice(&block_index.to_le_bytes());
    let hash = blake3::derive_key("Arsenic V2 Block Nonce", &material);
    hash[..24].try_into().expect("24 <= 32")
}

// ── Merkle tree ───────────────────────────────────────────────────────────

/// Compute the leaf hash: BLAKE3(encrypted_block).
fn compute_leaf(encrypted_block: &[u8]) -> [u8; 32] {
    *blake3::hash(encrypted_block).as_bytes()
}

/// Build the Merkle root from leaf hashes (binary tree, odd node promoted).
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&current[i]);
                combined[32..].copy_from_slice(&current[i + 1]);
                next.push(*blake3::hash(&combined).as_bytes());
            } else {
                next.push(current[i]); // promote odd leaf
            }
            i += 2;
        }
        current = next;
    }
    current[0]
}

// ── Block size selection ──────────────────────────────────────────────────

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
        _ => Err(CoreErr::DecryptFail(format!("Unknown block size ID: {id:#x}"))),
    }
}

// ── Read helpers ──────────────────────────────────────────────────────────

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

// ── Public encrypt/decrypt ────────────────────────────────────────────────

/// Encrypt a file using the Arsenic V2 format (two-pass, seekable output).
#[allow(clippy::too_many_lines)]
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
    // ── 1. Generate random material ───────────────────────────────────────
    let salt: [u8; 16] = random();
    let file_base_nonce: [u8; 24] = random();
    let kek_nonce: [u8; 12] = random();
    let mut dek: [u8; 32] = random();

    let (block_size, block_size_id) = select_block_params(filesize);

    // ── 2. Write placeholder header (256 bytes of zeros) ─────────────────
    output.write_all(&[0u8; TOTAL_HEADER_LEN])?;

    // ── 3. Pass 1: encrypt blocks, collect leaves ─────────────────────────
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut buf = vec![0u8; block_size];
    let mut block_index: u64 = 0;
    let mut total_read: u64 = 0;

    loop {
        let n = read_full(input, &mut buf)?;
        if n == 0 {
            break; // EOF exactly on a block boundary — no trailing empty block
        }
        total_read += n as u64;

        let plaintext = &buf[..n];
        let block_nonce = derive_block_nonce(&file_base_nonce, block_index);
        let block_key_bytes = derive_block_key(&dek, block_index);

        let cipher = XChaCha20Poly1305::new_from_slice(&block_key_bytes)
            .map_err(|_| CoreErr::CreateCipher)?;
        let nonce = XNonce::from_slice(&block_nonce);
        let aad = block_index.to_le_bytes();
        let payload = Payload { msg: plaintext, aad: &aad };
        let encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CoreErr::EncryptFail("Block encryption failed".into()))?;

        leaves.push(compute_leaf(&encrypted));
        output.write_all(&encrypted)?;
        block_index += 1;

        let pct = ((total_read as f32 / filesize as f32) * 95.0) as i32;
        ui.output(pct.min(95));

        if n < block_size {
            break;
        }
    }

    // ── 4. Pass 2: compute Merkle root, build and seal header ─────────────
    let root = merkle_root(&leaves);

    let env = EnvelopeContent {
        dek,
        merkle_root: root,
        original_size: filesize,
        compressed_size: total_read,
        block_size_id,
    };
    let env_pt = serialize_envelope(&env);

    // Derive KEK
    let kek = derive_kek(
        password.expose().as_bytes(),
        &salt,
        params.t_cost,
        params.m_cost,
        params.p_cost,
    )?;

    // Encrypt envelope with Serpent-GCM
    let serpent = SerpentGcm::new(kek.expose())?;
    let enc_env = serpent.encrypt(&kek_nonce, &[], &env_pt);
    assert_eq!(enc_env.len(), ENVELOPE_PT_LEN + 16);
    let enc_env_arr: [u8; ENVELOPE_PT_LEN + 16] =
        enc_env.try_into().expect("exactly 97 bytes");

    // Build public header and compute MAC
    let pub_header = PublicHeader {
        compression_id: COMPRESS_NONE,
        header_total_size: DEFAULT_HEADER_SIZE,
        salt,
        t_cost: params.t_cost,
        m_cost: params.m_cost,
        p_cost: params.p_cost,
        file_base_nonce,
        kek_nonce,
    };

    let prekey = compute_prekey(password.expose().as_bytes(), &salt);
    let pre_mac_bytes = super::header::serialize_pre_mac(&pub_header);
    let mac = compute_header_mac(&prekey, &pre_mac_bytes);

    let header_bytes = build_header_bytes(&pub_header, &mac, &enc_env_arr);

    // Seek back and write real header
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header_bytes)?;
    output.flush()?;

    // Zeroize sensitive material
    dek.zeroize();

    ui.output(100);
    Ok(())
}

/// Decrypt a file in Arsenic V2 format.
#[allow(clippy::too_many_lines)]
pub fn decrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
) -> Result<(), CoreErr>
where
    R: Read,
    W: Write,
{
    // ── 1. Read header ────────────────────────────────────────────────────
    let mut header_buf = [0u8; TOTAL_HEADER_LEN];
    input.read_exact(&mut header_buf).map_err(|_| CoreErr::BadSignature)?;

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env) = parse_header_bytes(&header_buf)?;

    // ── 2. Pre-authentication (DoS-immune MAC check) ──────────────────────
    let prekey = compute_prekey(password.expose().as_bytes(), &pub_hdr.salt);
    if !verify_header_mac(&prekey, &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    // ── 3. Sanity limits ──────────────────────────────────────────────────
    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Parameters exceed safety limits".into()));
    }

    // ── 4. Derive KEK with Argon2id ───────────────────────────────────────
    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;

    // ── 5. Decrypt envelope ───────────────────────────────────────────────
    let serpent = SerpentGcm::new(kek.expose())?;
    let env_enc: [u8; ENVELOPE_PT_LEN + 16] =
        enc_env.try_into().map_err(|_| CoreErr::DecryptFail("Envelope size".into()))?;
    let env_pt = serpent.decrypt(&pub_hdr.kek_nonce, &[], &env_enc)?;
    let env = deserialize_envelope(&env_pt)?;

    let block_size = block_size_from_id(env.block_size_id)?;
    let encrypted_block_size = block_size + 16; // plaintext + Poly1305 tag

    // ── 6. Decrypt payload blocks ─────────────────────────────────────────
    let num_blocks =
        (env.compressed_size + block_size as u64 - 1) / block_size as u64;

    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_blocks as usize);
    let mut total_read: u64 = 0;

    for block_index in 0..num_blocks {
        // Determine expected encrypted block size
        let is_last = block_index == num_blocks - 1;
        let expected_enc_size = if is_last {
            let last_pt = if env.compressed_size % block_size as u64 == 0 {
                block_size
            } else {
                (env.compressed_size % block_size as u64) as usize
            };
            last_pt + 16
        } else {
            encrypted_block_size
        };

        let mut enc_buf = vec![0u8; expected_enc_size];
        read_full(input, &mut enc_buf)?;
        total_read += enc_buf.len() as u64;

        leaves.push(compute_leaf(&enc_buf));

        let block_key_bytes = derive_block_key(&env.dek, block_index);
        let block_nonce = derive_block_nonce(&pub_hdr.file_base_nonce, block_index);
        let cipher = XChaCha20Poly1305::new_from_slice(&block_key_bytes)
            .map_err(|_| CoreErr::CreateCipher)?;
        let nonce = XNonce::from_slice(&block_nonce);
        let aad = block_index.to_le_bytes();
        let payload = Payload { msg: &enc_buf, aad: &aad };
        let plaintext = cipher.decrypt(nonce, payload).map_err(|_| CoreErr::DecryptionError)?;

        output.write_all(&plaintext)?;

        let pct = ((total_read as f32 / filesize as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    // ── 7. Verify Merkle root ─────────────────────────────────────────────
    let computed_root = merkle_root(&leaves);
    if computed_root != env.merkle_root {
        return Err(CoreErr::DecryptFail("Merkle root mismatch".into()));
    }

    output.flush()?;
    ui.output(100);
    Ok(())
}

/// Rekey an Arsenic V2 file in-place: change the password without touching the payload.
///
/// Only the 256-byte header is rewritten. The payload blocks and their DEK are untouched.
/// Progress emitted: 0% → 50% (after old KEK derived) → 100%.
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

    // ── 1. Read and parse the header ──────────────────────────────────────
    file.seek(SeekFrom::Start(0))?;
    let mut header_buf = [0u8; TOTAL_HEADER_LEN];
    file.read_exact(&mut header_buf).map_err(|_| CoreErr::BadSignature)?;
    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env) = parse_header_bytes(&header_buf)?;

    // ── 2. Safety limits + pre-auth MAC check (DoS-immune) ───────────────
    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail("Parameters exceed safety limits".into()));
    }
    let prekey_old = compute_prekey(old_password.expose().as_bytes(), &pub_hdr.salt);
    if !verify_header_mac(&prekey_old, &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    // ── 3. Derive old KEK and decrypt the envelope (recovers raw DEK) ─────
    let kek_old = derive_kek(
        old_password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    let serpent_old = SerpentGcm::new(kek_old.expose())?;
    let env_pt = serpent_old.decrypt(&pub_hdr.kek_nonce, &[], &enc_env)?;

    ui.output(50);

    // ── 4. Fresh salt + nonce; derive new KEK; re-encrypt envelope ────────
    let new_salt: [u8; 16] = random();
    let new_kek_nonce: [u8; 12] = random();
    let kek_new = derive_kek(
        new_password.expose().as_bytes(),
        &new_salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    let serpent_new = SerpentGcm::new(kek_new.expose())?;
    let enc_env_new = serpent_new.encrypt(&new_kek_nonce, &[], &env_pt);
    let enc_env_arr: [u8; ENVELOPE_PT_LEN + GCM_TAG] =
        enc_env_new.try_into().expect("encrypt always produces exactly ENVELOPE_ENC_LEN bytes");

    // ── 5. Build new public header and compute new MAC ────────────────────
    let new_pub_hdr = PublicHeader {
        compression_id: pub_hdr.compression_id,
        header_total_size: pub_hdr.header_total_size,
        salt: new_salt,
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
        file_base_nonce: pub_hdr.file_base_nonce,
        kek_nonce: new_kek_nonce,
    };
    let prekey_new = compute_prekey(new_password.expose().as_bytes(), &new_salt);
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(&prekey_new, &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &enc_env_arr);

    // ── 6. Write the new 256-byte header in-place ─────────────────────────
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&new_header)?;
    file.flush()?;

    ui.output(100);
    Ok(())
}
