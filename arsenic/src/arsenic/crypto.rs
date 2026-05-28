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
    build_header_bytes, compute_header_mac, compute_prekey, deserialize_meta_tlv,
    parse_header_bytes, serialize_meta_tlv, serialize_pre_mac, verify_header_mac, EnvelopeContent,
    EnvelopeMetadata, PublicHeader, GCM_TAG, MERKLE_V1, META_TLV_MANDATORY_PT_LEN,
    MIN_HEADER_TOTAL_SIZE, PUB_HEADER_LEN, WRAPPED_DEK_LEN,
};
use super::{
    CipherId, Compression, BLOCK_ID_32MB, BLOCK_ID_4MB, BLOCK_SIZE_32MB, BLOCK_SIZE_4MB,
    LARGE_FILE_THRESHOLD, MAX_ARGON2_RAM_KB, MAX_HEADER_TOTAL_SIZE,
};

type BlockResults = Result<Vec<(Vec<u8>, [u8; 32])>, CoreErr>;

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

// ── ProtectedMetadata key and nonce derivation ────────────────────────────────

/// MetaKey: derived from DEK, used to encrypt/decrypt ProtectedMetadata.
/// Independent of the password; never changes as long as DEK is unchanged.
fn derive_meta_key(dek: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("Arsenic V1 Metadata Key", dek)
}

/// MetaNonce: deterministic 12-byte nonce for ProtectedMetadata AEAD.
/// Safe because DEK is unique per file and MetaKey is unique per DEK.
fn derive_meta_nonce(dek: &[u8; 32]) -> [u8; 12] {
    let h = blake3::derive_key("Arsenic V1 Meta Nonce", dek);
    h[..12].try_into().expect("12 <= 32")
}

// ── Merkle v1 — domain-separated BLAKE3 ──────────────────────────────────────
//
// Algorithm spec (stored as MERKLE_V1 = 0x01 in ProtectedMetadata TLV):
//
//   Leaf   = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", ciphertext)
//   Node   = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", left_32 || right_32)
//   Odd    = last node promoted without hashing (v1 promotion rule)
//   Empty  = [0u8; 32] sentinel for zero-block files
//   Endian = big-endian child order (left child first in the 64-byte node input)
//
// Domain separation via derive_key ensures leaf hashes and internal node hashes
// are in disjoint output domains, ruling out second-preimage attacks where a
// crafted 64-byte block B = left || right satisfies BLAKE3(B) = internal node.

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
        0 => [0u8; 32], // empty file sentinel
        1 => leaves[0], // single leaf is its own root
        _ => {
            let mut current = leaves.to_vec();
            while current.len() > 1 {
                let mut next = Vec::with_capacity(current.len().div_ceil(2));
                let mut i = 0;
                while i < current.len() {
                    if i + 1 < current.len() {
                        next.push(merkle_node(&current[i], &current[i + 1]));
                    } else {
                        // Odd-count promotion: the last node is carried up unchanged.
                        // With domain separation this is safe — a promoted leaf hash
                        // cannot be confused with a node hash.
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

/// Read the full variable-length header from a reader.
fn read_header<R: Read>(input: &mut R) -> Result<Vec<u8>, CoreErr> {
    let mut prefix = [0u8; 12];
    input
        .read_exact(&mut prefix)
        .map_err(|_| CoreErr::BadSignature)?;

    let header_total_size = u16::from_le_bytes([prefix[10], prefix[11]]) as usize;

    if header_total_size < MIN_HEADER_TOTAL_SIZE
        || header_total_size > MAX_HEADER_TOTAL_SIZE as usize
    {
        return Err(CoreErr::DecryptFail(format!(
            "header_total_size {header_total_size} out of range [{MIN_HEADER_TOTAL_SIZE}, {}]",
            MAX_HEADER_TOTAL_SIZE
        )));
    }

    let mut header_buf = vec![0u8; header_total_size];
    header_buf[..12].copy_from_slice(&prefix);
    input
        .read_exact(&mut header_buf[12..])
        .map_err(|_| CoreErr::BadSignature)?;
    Ok(header_buf)
}

// ── Envelope size helpers ─────────────────────────────────────────────────────

/// Extra plaintext bytes from optional metadata fields (for header size pre-computation).
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

// ── Envelope decryption ───────────────────────────────────────────────────────

/// Decrypt and parse the envelope region:
///   enc_region = WrappedDEK(48 bytes) || ProtectedMetadata(variable)
fn decrypt_envelope(
    hdr_cipher: CipherId,
    kek: &[u8; 32],
    kek_nonce: &[u8; 12],
    enc_region: &[u8],
) -> Result<EnvelopeContent, CoreErr> {
    if enc_region.len() < WRAPPED_DEK_LEN {
        return Err(CoreErr::DecryptFail(
            "Envelope region too short for keyslot".into(),
        ));
    }
    let (wrapped_dek_bytes, protected_meta_bytes) = enc_region.split_at(WRAPPED_DEK_LEN);

    // 1. Unwrap DEK from keyslot using KEK (password-derived).
    let dek_vec =
        cipher_dispatch::envelope_decrypt(hdr_cipher, kek, kek_nonce, &[], wrapped_dek_bytes)?;
    if dek_vec.len() != 32 {
        return Err(CoreErr::DecryptFail(
            "WrappedDEK plaintext must be 32 bytes".into(),
        ));
    }
    let dek: [u8; 32] = dek_vec.try_into().unwrap();

    // 2. Decrypt ProtectedMetadata with keys derived from DEK (not from password).
    let meta_key = derive_meta_key(&dek);
    let meta_nonce = derive_meta_nonce(&dek);
    let meta_pt = cipher_dispatch::envelope_decrypt(
        hdr_cipher,
        &meta_key,
        &meta_nonce,
        &[],
        protected_meta_bytes,
    )?;

    deserialize_meta_tlv(&meta_pt, dek)
}

// ── Public encrypt/decrypt/rekey ──────────────────────────────────────────────

/// Encrypt a file using the Arsenic V1 format (parallel block encryption).
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
    let salt: [u8; 16] = random();
    let file_base_nonce: [u8; 24] = random();
    let kek_nonce: [u8; 12] = random();
    let mut dek: [u8; 32] = random();

    let (block_size, block_size_id) = select_block_params(filesize);
    let pld_cipher = params.pld_cipher;

    // Pre-compute header size before writing the placeholder.
    let meta = &params.metadata;
    let meta_pt_len = META_TLV_MANDATORY_PT_LEN + metadata_extra_pt_len(meta);
    let protected_meta_enc_len = meta_pt_len + GCM_TAG;
    let header_total_size = PUB_HEADER_LEN + WRAPPED_DEK_LEN + protected_meta_enc_len;
    if header_total_size > MAX_HEADER_TOTAL_SIZE as usize {
        return Err(CoreErr::EncryptFail("Metadata too large for header".into()));
    }
    output.write_all(&vec![0u8; header_total_size])?;

    // ── Read input into fixed-size blocks ─────────────────────────────────
    // Blocks are based on the original plaintext size.
    // Each block is independently compressed (if enabled) and encrypted —
    // workers are fully independent and can run in parallel.
    let mut raw_blocks: Vec<Vec<u8>> = Vec::new();
    let mut total_read: u64 = 0;
    {
        let mut buf = vec![0u8; block_size];
        loop {
            let n = read_full(input, &mut buf)?;
            if n == 0 {
                break;
            }
            total_read += n as u64;
            raw_blocks.push(buf[..n].to_vec());
            if n < block_size {
                break;
            }
        }
    }

    let compression = params.compression; // Copy — captured by value in par_iter closure
    let compression_id = compression.to_byte();

    // ── Parallel compress (optional) + encrypt ────────────────────────────
    // For Compression::Zstd each block is compressed independently before
    // being passed to the AEAD. Memory usage is O(block_size), not O(file).
    let enc_results: BlockResults = raw_blocks
        .into_par_iter()
        .enumerate()
        .map(|(block_index, plaintext)| {
            let block_nonce = derive_block_nonce(&file_base_nonce, block_index as u64);
            let block_key_bytes = derive_block_key(&dek, block_index as u64);
            let aad = (block_index as u64).to_le_bytes();

            let data_to_encrypt = match compression {
                Compression::None => plaintext,
                Compression::Zstd(level) => zstd::bulk::compress(&plaintext, level)
                    .map_err(|e| CoreErr::EncryptFail(format!("zstd: {e}")))?,
            };

            let encrypted = cipher_dispatch::block_encrypt(
                pld_cipher,
                &block_key_bytes,
                &block_nonce,
                &aad,
                &data_to_encrypt,
            )?;
            let leaf = merkle_leaf(&encrypted);
            Ok((encrypted, leaf))
        })
        .collect();

    let enc_results = enc_results?;
    let num_blocks = enc_results.len();

    // ── Write encrypted blocks ────────────────────────────────────────────
    // For compressed blocks each ciphertext has a variable size, so a 4-byte
    // little-endian length prefix is prepended. Uncompressed blocks retain the
    // current fixed-size layout (no prefix).
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_blocks);
    for (i, (encrypted, leaf)) in enc_results.into_iter().enumerate() {
        if matches!(compression, Compression::Zstd(_)) {
            let size = u32::try_from(encrypted.len())
                .map_err(|_| CoreErr::EncryptFail("Encrypted block exceeds u32 size".into()))?;
            output.write_all(&size.to_le_bytes())?;
        }
        output.write_all(&encrypted)?;
        leaves.push(leaf);
        let pct = (((i + 1) as f32 / num_blocks.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    let root = merkle_root_v1(&leaves);

    // Build the ProtectedMetadata TLV (no DEK inside — DEK is in the keyslot).
    // compressed_size == original_size for per-block compression: we split the
    // original plaintext into fixed blocks, not the compressed output.
    let env = EnvelopeContent {
        dek,
        merkle_root: root,
        original_size: filesize,
        compressed_size: total_read,
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

    // Keyslot: wrap DEK under KEK.
    let wrapped_dek =
        cipher_dispatch::envelope_encrypt(params.hdr_cipher, kek.expose(), &kek_nonce, &[], &dek)?;

    // ProtectedMetadata: encrypt TLV under MetaKey derived from DEK.
    let meta_key = derive_meta_key(&dek);
    let meta_nonce = derive_meta_nonce(&dek);
    let protected_meta = cipher_dispatch::envelope_encrypt(
        params.hdr_cipher,
        &meta_key,
        &meta_nonce,
        &[],
        &meta_tlv,
    )?;

    // Assemble the full envelope region: WrappedDEK || ProtectedMetadata.
    let enc_envelope: Vec<u8> = wrapped_dek
        .iter()
        .chain(protected_meta.iter())
        .copied()
        .collect();

    let pub_header = PublicHeader {
        compression_id,
        header_total_size: header_total_size as u16,
        salt,
        t_cost: params.t_cost,
        m_cost: params.m_cost,
        p_cost: params.p_cost,
        file_base_nonce,
        kek_nonce,
        hdr_cipher_id: params.hdr_cipher.to_byte(),
        pld_cipher_id: params.pld_cipher.to_byte(),
    };

    let prekey = compute_prekey(password.expose().as_bytes(), &salt)?;
    let pre_mac_bytes = serialize_pre_mac(&pub_header);
    let mac = compute_header_mac(&prekey, &pre_mac_bytes);
    let header_bytes = build_header_bytes(&pub_header, &mac, &enc_envelope);

    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header_bytes)?;
    output.flush()?;

    dek.zeroize();
    ui.output(100);
    Ok(())
}

/// Decrypt an Arsenic V1 file (parallel block decryption).
///
/// Returns the optional metadata stored in the ProtectedMetadata section.
pub fn decrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    _filesize: u64,
) -> Result<EnvelopeMetadata, CoreErr>
where
    R: Read,
    W: Write,
{
    let header_buf = read_header(input)?;
    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;

    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;
    let pld_cipher = CipherId::from_byte(pub_hdr.pld_cipher_id)?;

    // Sanity limits checked BEFORE the tiny Argon2id pre-auth to avoid
    // allocating e.g. 8 GB for PREKEY_M_COST_KB on a malicious header.
    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail(
            "Parameters exceed safety limits".into(),
        ));
    }

    // Tiny Argon2id pre-authentication: requires real KDF work so the HeaderMAC
    // cannot serve as a fast offline brute-force oracle.
    let prekey = compute_prekey(password.expose().as_bytes(), &pub_hdr.salt)?;
    if !verify_header_mac(&prekey, &pre_mac_bytes, &stored_mac) {
        return Err(CoreErr::DecryptionError);
    }

    let kek = derive_kek(
        password.expose().as_bytes(),
        &pub_hdr.salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;

    let env = decrypt_envelope(
        hdr_cipher,
        kek.expose(),
        &pub_hdr.kek_nonce,
        &enc_env_region,
    )?;

    let block_size = block_size_from_id(env.block_size_id)?;
    let dek = env.dek;
    let file_base_nonce = pub_hdr.file_base_nonce;

    let compression = Compression::from_byte(pub_hdr.compression_id)?;

    // ── Read encrypted blocks ─────────────────────────────────────────────
    // Uncompressed: fixed-size blocks (current format, no size prefix).
    // Per-block zstd: variable-size blocks, each preceded by a 4-byte LE size.
    // In both cases all blocks are collected before parallel decrypt so that
    // Rayon can process them in any order.
    let encrypted_blocks: Vec<Vec<u8>> = match compression {
        Compression::None => {
            // num_blocks derived from compressed_size (= original_size for plain files).
            let num_blocks = env.compressed_size.div_ceil(block_size as u64);
            let encrypted_block_size = block_size + 16;
            let mut blocks = Vec::with_capacity(num_blocks as usize);
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
                blocks.push(enc_buf);
            }
            blocks
        }
        Compression::Zstd(_) => {
            // num_blocks derived from original_size: we split the original plaintext
            // into fixed blocks before compression, so the block count is determined
            // by the uncompressed size, not the compressed sizes.
            let num_blocks = env.original_size.div_ceil(block_size as u64);
            let mut blocks = Vec::with_capacity(num_blocks as usize);
            for _ in 0..num_blocks {
                // Read the 4-byte little-endian size prefix.
                let mut size_buf = [0u8; 4];
                read_full(input, &mut size_buf)?;
                let enc_size = u32::from_le_bytes(size_buf) as usize;
                let mut enc_buf = vec![0u8; enc_size];
                read_full(input, &mut enc_buf)?;
                blocks.push(enc_buf);
            }
            blocks
        }
    };

    // ── Parallel decrypt (+ decompress for zstd) ──────────────────────────
    // The Merkle leaf is computed over the raw AEAD ciphertext — identical
    // to the no-compression path since AEAD wraps the (possibly compressed) data.
    let dec_results: BlockResults = encrypted_blocks
        .into_par_iter()
        .enumerate()
        .map(|(block_index, enc_buf)| {
            let leaf = merkle_leaf(&enc_buf);
            let block_key_bytes = derive_block_key(&dek, block_index as u64);
            let block_nonce = derive_block_nonce(&file_base_nonce, block_index as u64);
            let aad = (block_index as u64).to_le_bytes();

            let decrypted = cipher_dispatch::block_decrypt(
                pld_cipher,
                &block_key_bytes,
                &block_nonce,
                &aad,
                &enc_buf,
            )?;

            let plaintext = match compression {
                Compression::None => decrypted,
                Compression::Zstd(_) => {
                    // Each block decompresses to at most block_size bytes.
                    zstd::bulk::decompress(&decrypted, block_size)
                        .map_err(|e| CoreErr::DecryptFail(format!("zstd: {e}")))?
                }
            };

            Ok((plaintext, leaf))
        })
        .collect();

    let dec_results = dec_results?;
    let num_results = dec_results.len();

    // ── Verify Merkle root BEFORE writing any plaintext ───────────────────
    let leaves: Vec<[u8; 32]> = dec_results.iter().map(|(_, l)| *l).collect();
    let computed_root = merkle_root_v1(&leaves);
    if computed_root != env.merkle_root {
        return Err(CoreErr::DecryptFail("Merkle root mismatch".into()));
    }

    // ── Write plaintext blocks ────────────────────────────────────────────
    for (i, (plaintext, _)) in dec_results.into_iter().enumerate() {
        output.write_all(&plaintext)?;
        let pct = (((i + 1) as f32 / num_results.max(1) as f32) * 95.0) as i32;
        ui.output(pct.min(95));
    }

    output.flush()?;
    ui.output(100);
    Ok(env.metadata())
}

/// Rekey an Arsenic V1 file in-place: change the password without touching the payload
/// or the ProtectedMetadata.
///
/// LUKS-style keyslot replacement: only the 48-byte WrappedDEK is re-encrypted
/// under the new KEK. ProtectedMetadata bytes are copied unchanged — they are
/// bound to the DEK, not to the password.
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
    let _header_total_size = header_buf.len();

    let (pub_hdr, pre_mac_bytes, stored_mac, enc_env_region) = parse_header_bytes(&header_buf)?;
    let hdr_cipher = CipherId::from_byte(pub_hdr.hdr_cipher_id)?;

    if pub_hdr.m_cost > MAX_ARGON2_RAM_KB || pub_hdr.header_total_size > MAX_HEADER_TOTAL_SIZE {
        return Err(CoreErr::DecryptFail(
            "Parameters exceed safety limits".into(),
        ));
    }

    let prekey_old = compute_prekey(old_password.expose().as_bytes(), &pub_hdr.salt)?;
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

    let new_salt: [u8; 16] = random();
    let new_kek_nonce: [u8; 12] = random();
    let kek_new = derive_kek(
        new_password.expose().as_bytes(),
        &new_salt,
        pub_hdr.t_cost,
        pub_hdr.m_cost,
        pub_hdr.p_cost,
    )?;

    // 1. Unwrap DEK from the keyslot using the old KEK.
    // 2. Re-wrap DEK under the new KEK.
    // 3. Copy ProtectedMetadata bytes as-is — no decryption, no re-encryption.
    //    MetaKey = f(DEK), not f(password), so it is unaffected by the password change.
    let (wrapped_dek_bytes, protected_meta_bytes) = enc_env_region.split_at(WRAPPED_DEK_LEN);

    let mut dek_vec = cipher_dispatch::envelope_decrypt(
        hdr_cipher,
        kek_old.expose(),
        &pub_hdr.kek_nonce,
        &[],
        wrapped_dek_bytes,
    )?;

    let new_wrapped_dek = cipher_dispatch::envelope_encrypt(
        hdr_cipher,
        kek_new.expose(),
        &new_kek_nonce,
        &[],
        &dek_vec,
    )?;

    dek_vec.zeroize();

    // Assemble: new keyslot || unchanged ProtectedMetadata.
    let new_enc_envelope: Vec<u8> = new_wrapped_dek
        .iter()
        .chain(protected_meta_bytes.iter())
        .copied()
        .collect();

    let new_pub_hdr = PublicHeader {
        compression_id: pub_hdr.compression_id,
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
    let prekey_new = compute_prekey(new_password.expose().as_bytes(), &new_salt)?;
    let new_pre_mac = serialize_pre_mac(&new_pub_hdr);
    let new_mac = compute_header_mac(&prekey_new, &new_pre_mac);
    let new_header = build_header_bytes(&new_pub_hdr, &new_mac, &new_enc_envelope);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&new_header)?;
    file.flush()?;

    ui.output(100);
    Ok(())
}
