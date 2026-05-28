use std::io::{Read, Seek, SeekFrom, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::random;
use rayon::prelude::*;
use zeroize::Zeroize;

use crate::errors::CoreErr;
use crate::secret::Secret;
use crate::Ui;

use super::cipher_dispatch;
use super::header::{
    build_header_bytes, compute_header_mac, compute_prekey, deserialize_envelope,
    parse_header_bytes, serialize_envelope, serialize_pre_mac, verify_header_mac, EnvelopeContent,
    PublicHeader, COMPRESS_NONE, DEFAULT_HEADER_SIZE, ENVELOPE_ENC_LEN, ENVELOPE_PT_LEN, GCM_TAG,
    TOTAL_HEADER_LEN,
};
use super::{
    CipherId, BLOCK_ID_32MB, BLOCK_ID_4MB, BLOCK_SIZE_32MB, BLOCK_SIZE_4MB, LARGE_FILE_THRESHOLD,
    MAX_ARGON2_RAM_KB, MAX_HEADER_TOTAL_SIZE,
};

type BlockResults = Result<Vec<(Vec<u8>, [u8; 32])>, CoreErr>;

// ── Key / nonce derivation ────────────────────────────────────────────────

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
    let hash = blake3::derive_key("Arsenic V2 Block Nonce", &material);
    hash[..24].try_into().expect("24 <= 32")
}

// ── Merkle tree ───────────────────────────────────────────────────────────

fn compute_leaf(encrypted_block: &[u8]) -> [u8; 32] {
    *blake3::hash(encrypted_block).as_bytes()
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&current[i]);
                combined[32..].copy_from_slice(&current[i + 1]);
                next.push(*blake3::hash(&combined).as_bytes());
            } else {
                next.push(current[i]);
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
        _ => Err(CoreErr::DecryptFail(format!(
            "Unknown block size ID: {id:#x}"
        ))),
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

/// Encrypt a file using the Arsenic V2 format (parallel block encryption).
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
    let pld_cipher = params.pld_cipher; // Copy — captured by value in par_iter closure

    // ── 2. Write placeholder header (256 bytes of zeros) ─────────────────
    output.write_all(&[0u8; TOTAL_HEADER_LEN])?;

    // ── 3. Read all input blocks ──────────────────────────────────────────
    let mut raw_blocks: Vec<Vec<u8>> = Vec::new();
    let mut total_read: u64 = 0;
    loop {
        let mut buf = vec![0u8; block_size];
        let n = read_full(input, &mut buf)?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        buf.truncate(n);
        raw_blocks.push(buf);
        if n < block_size {
            break;
        }
    }

    // ── 4. Parallel encrypt — all blocks are independent ─────────────────
    // dek and file_base_nonce are [u8; N] (Copy + Send) — captured by value.
    // pld_cipher is CipherId (Copy + Send) — captured by value.
    // Progress is reported in step 5 from the main thread; Ui need not be Sync.
    let enc_results: BlockResults = raw_blocks
        .into_par_iter()
        .enumerate()
        .map(|(block_index, plaintext)| {
            let block_nonce = derive_block_nonce(&file_base_nonce, block_index as u64);
            let block_key_bytes = derive_block_key(&dek, block_index as u64);
            let aad = (block_index as u64).to_le_bytes();
            let encrypted =
                cipher_dispatch::block_encrypt(pld_cipher, &block_key_bytes, &block_nonce, &aad, &plaintext)?;
            let leaf = compute_leaf(&encrypted);
            Ok((encrypted, leaf))
        })
        .collect();

    let enc_results = enc_results?;
    let num_blocks = enc_results.len();

    // ── 5. Write encrypted blocks sequentially and collect leaves ─────────
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_blocks);
    for (i, (encrypted, leaf)) in enc_results.into_iter().enumerate() {
        output.write_all(&encrypted)?;
        leaves.push(leaf);
        let pct = (((i + 1) as f32 / num_blocks.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    // ── 6. Compute Merkle root, build and seal header ─────────────────────
    let root = merkle_root(&leaves);

    let env = EnvelopeContent {
        dek,
        merkle_root: root,
        original_size: filesize,
        compressed_size: total_read,
        block_size_id,
    };
    let env_pt = serialize_envelope(&env);

    let kek = derive_kek(
        password.expose().as_bytes(),
        &salt,
        params.t_cost,
        params.m_cost,
        params.p_cost,
    )?;

    let enc_env =
        cipher_dispatch::envelope_encrypt(params.hdr_cipher, kek.expose(), &kek_nonce, &[], &env_pt)?;
    assert_eq!(enc_env.len(), ENVELOPE_PT_LEN + GCM_TAG);
    let enc_env_arr: [u8; ENVELOPE_PT_LEN + GCM_TAG] =
        enc_env.try_into().expect("exactly 97 bytes");

    let pub_header = PublicHeader {
        compression_id: COMPRESS_NONE,
        header_total_size: DEFAULT_HEADER_SIZE,
        salt,
        t_cost: params.t_cost,
        m_cost: params.m_cost,
        p_cost: params.p_cost,
        file_base_nonce,
        kek_nonce,
        hdr_cipher_id: params.hdr_cipher.to_byte(),
        pld_cipher_id: params.pld_cipher.to_byte(),
    };

    let prekey = compute_prekey(password.expose().as_bytes(), &salt);
    let pre_mac_bytes = serialize_pre_mac(&pub_header);
    let mac = compute_header_mac(&prekey, &pre_mac_bytes);

    let header_bytes = build_header_bytes(&pub_header, &mac, &enc_env_arr);

    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header_bytes)?;
    output.flush()?;

    dek.zeroize();
    ui.output(100);
    Ok(())
}

/// Decrypt a file in Arsenic V2 format (parallel block decryption).
///
/// All blocks are decrypted in parallel. The Merkle root is verified before
/// any plaintext is written to `output`.
pub fn decrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    _filesize: u64,
) -> Result<(), CoreErr>
where
    R: Read,
    W: Write,
{
    // ── 1. Read and parse header ──────────────────────────────────────────
    let mut header_buf = [0u8; TOTAL_HEADER_LEN];
    input
        .read_exact(&mut header_buf)
        .map_err(|_| CoreErr::BadSignature)?;

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env) = parse_header_bytes(&header_buf)?;

    // ── 2. Resolve cipher IDs ─────────────────────────────────────────────
    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let pld_cipher = CipherId::from_byte(pub_hdr.pld_cipher_id)?;

    // ── 3. Pre-authentication (DoS-immune MAC check) ──────────────────────
    let prekey = compute_prekey(password.expose().as_bytes(), &pub_hdr.salt);
    if !verify_header_mac(&prekey, &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    // ── 4. Sanity limits ──────────────────────────────────────────────────
    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail(
            "Parameters exceed safety limits".into(),
        ));
    }

    // ── 5. Derive KEK with Argon2id ───────────────────────────────────────
    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;

    // ── 6. Decrypt envelope ───────────────────────────────────────────────
    if enc_env.len() != ENVELOPE_ENC_LEN {
        return Err(CoreErr::DecryptFail("Envelope size mismatch".into()));
    }
    let env_pt =
        cipher_dispatch::envelope_decrypt(hdr_cipher, kek.expose(), &pub_hdr.kek_nonce, &[], &enc_env)?;
    let env = deserialize_envelope(&env_pt)?;

    let block_size = block_size_from_id(env.block_size_id)?;
    let encrypted_block_size = block_size + 16;
    let num_blocks = env.compressed_size.div_ceil(block_size as u64);

    // ── 7. Read all encrypted blocks ─────────────────────────────────────
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks as usize);
    for block_index in 0..num_blocks {
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
        encrypted_blocks.push(enc_buf);
    }

    // ── 8. Parallel decrypt + leaf computation ────────────────────────────
    // dek, file_base_nonce, and pld_cipher are all Copy + Send — captured by value.
    let dek = env.dek;
    let file_base_nonce = pub_hdr.file_base_nonce;

    let dec_results: BlockResults = encrypted_blocks
        .into_par_iter()
        .enumerate()
        .map(|(block_index, enc_buf)| {
            let leaf = compute_leaf(&enc_buf);
            let block_key_bytes = derive_block_key(&dek, block_index as u64);
            let block_nonce = derive_block_nonce(&file_base_nonce, block_index as u64);
            let aad = (block_index as u64).to_le_bytes();
            let plaintext =
                cipher_dispatch::block_decrypt(pld_cipher, &block_key_bytes, &block_nonce, &aad, &enc_buf)?;
            Ok((plaintext, leaf))
        })
        .collect();

    let dec_results = dec_results?;
    let num_results = dec_results.len();

    // ── 9. Verify Merkle root BEFORE writing any plaintext ────────────────
    let leaves: Vec<[u8; 32]> = dec_results.iter().map(|(_, l)| *l).collect();
    let computed_root = merkle_root(&leaves);
    if computed_root != env.merkle_root {
        return Err(CoreErr::DecryptFail("Merkle root mismatch".into()));
    }

    // ── 10. Write plaintext blocks sequentially ───────────────────────────
    for (i, (plaintext, _)) in dec_results.into_iter().enumerate() {
        output.write_all(&plaintext)?;
        let pct = (((i + 1) as f32 / num_results.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    output.flush()?;
    ui.output(100);
    Ok(())
}

/// Rekey an Arsenic V2 file in-place: change the password without touching the payload.
///
/// Cipher algorithm choices are preserved — only the salt, kek_nonce, and
/// encrypted envelope change.
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
    let mut header_buf = [0u8; TOTAL_HEADER_LEN];
    file.read_exact(&mut header_buf)
        .map_err(|_| CoreErr::BadSignature)?;
    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env) = parse_header_bytes(&header_buf)?;

    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;

    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail(
            "Parameters exceed safety limits".into(),
        ));
    }
    let prekey_old = compute_prekey(old_password.expose().as_bytes(), &pub_hdr.salt);
    if !verify_header_mac(&prekey_old, &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let kek_old = derive_kek(
        old_password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    let env_pt =
        cipher_dispatch::envelope_decrypt(hdr_cipher, kek_old.expose(), &pub_hdr.kek_nonce, &[], &enc_env)?;

    ui.output(50);

    let new_salt: [u8; 16] = random();
    let new_kek_nonce: [u8; 12] = random();
    let kek_new = derive_kek(
        new_password.expose().as_bytes(),
        &new_salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;
    let enc_env_new =
        cipher_dispatch::envelope_encrypt(hdr_cipher, kek_new.expose(), &new_kek_nonce, &[], &env_pt)?;
    let enc_env_arr: [u8; ENVELOPE_PT_LEN + GCM_TAG] = enc_env_new
        .try_into()
        .expect("encrypt always produces exactly ENVELOPE_ENC_LEN bytes");

    let new_pub_hdr = PublicHeader {
        compression_id: pub_hdr.compression_id,
        header_total_size: pub_hdr.header_total_size,
        salt: new_salt,
        t_cost: pub_hdr.t_cost,
        m_cost: pub_hdr.m_cost,
        p_cost: pub_hdr.p_cost,
        file_base_nonce: pub_hdr.file_base_nonce,
        kek_nonce: new_kek_nonce,
        hdr_cipher_id: pub_hdr.hdr_cipher_id, // preserved
        pld_cipher_id: pub_hdr.pld_cipher_id, // preserved
    };
    let prekey_new = compute_prekey(new_password.expose().as_bytes(), &new_salt);
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(&prekey_new, &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &enc_env_arr);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&new_header)?;
    file.flush()?;

    ui.output(100);
    Ok(())
}
