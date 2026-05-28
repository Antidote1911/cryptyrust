use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::errors::CoreErr;

type HmacSha256 = Hmac<Sha256>;
type ParsedHeader = (PublicHeader, [u8; PRE_MAC_LEN], [u8; 32], Vec<u8>);

pub const MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"
pub const VERSION: [u8; 2] = [0x00, 0x01];
pub const KDF_ID_ARGON2ID: u8 = 0x01;
#[allow(dead_code)]
pub const HDR_CIPHER_DEOXYS_II: u8 = 0x02;
#[allow(dead_code)]
pub const PLD_CIPHER_XCHACHA20: u8 = 0x03;
#[allow(dead_code)]
pub const CIPHER_AES256_GCM_SIV: u8 = 0x04;
pub const COMPRESS_NONE: u8 = 0x00;
pub const COMPRESS_ZSTD: u8 = 0x01;

/// Tiny Argon2id parameters for the pre-authentication key.
///
/// These are intentionally much cheaper than the full KEK derivation so that a
/// wrong password is rejected quickly, while still requiring real KDF work.
/// A pure HMAC over the password would be a fast offline oracle (billions of
/// checks/s on GPU); with tiny Argon2id the attacker is limited to ~15 000/s
/// (RTX 4090, m = 8 MB), a ×1 300 000 improvement over the HMAC baseline.
///
/// Using the same 16-byte header salt as the full KEK derivation is safe:
/// Argon2id encodes t/m/p into its output, so PreKey ≠ KEK despite identical
/// (password, salt) inputs.
pub const PREKEY_T_COST: u32 = 1;
pub const PREKEY_M_COST_KB: u32 = 8 * 1024; // 8 MB — ~2 ms on modern CPU
pub const PREKEY_P_COST: u32 = 1;

/// Byte length of the public (pre-MAC) section (0x00..0x4B inclusive).
pub const PRE_MAC_LEN: usize = 0x4C; // 76
/// Byte length of the full public header including MAC (0x00..0x6B inclusive).
pub const PUB_HEADER_LEN: usize = 0x6C; // 108
/// GCM tag size.
pub const GCM_TAG: usize = 16;

// ── Keyslot format constants ──────────────────────────────────────────────────

/// WrappedDEK keyslot size: AEAD_KEK(32-byte DEK) = 32 + 16-byte tag = 48 bytes.
/// This is the ONLY section that changes on a password change (rekey).
pub const WRAPPED_DEK_LEN: usize = 32 + GCM_TAG; // 48

/// Merkle tree algorithm version stored in ProtectedMetadata.
///
/// v1 specification (current):
///   Leaf   = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", ciphertext)
///   Node   = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", left_32 || right_32)
///   Odd    = last node promoted without hashing (safe: domain separation prevents
///            leaf-node confusion; documented as the v1 promotion rule)
///   Empty  = [0u8; 32]  (well-known sentinel for zero-block files)
///   Endian = big-endian child order (left child first in the 64-byte node input)
pub const MERKLE_V1: u8 = 0x01;

/// Mandatory TLV bytes for ProtectedMetadata (no DEK — it lives in the keyslot):
///   MerkleRoot(32+2) + OrigSize(8+2) + CompSize(8+2) + BlockSizeId(1+2)
///   + MerkleAlgoId(1+2) = 60
pub const META_TLV_MANDATORY_PT_LEN: usize = 60;

/// Minimum total header size (no optional fields):
///   PUB_HEADER_LEN(108) + WRAPPED_DEK_LEN(48) + META_TLV_MANDATORY_PT_LEN(60) + GCM_TAG(16)
pub const MIN_HEADER_TOTAL_SIZE: usize =
    PUB_HEADER_LEN + WRAPPED_DEK_LEN + META_TLV_MANDATORY_PT_LEN + GCM_TAG;

/// TLV tag identifiers for the ProtectedMetadata section.
/// The DEK is NOT in the TLV — it lives in the separate WrappedDEK keyslot.
pub mod tlv_tags {
    /// BLAKE3 Merkle root (32 bytes) — mandatory.
    pub const MERKLE_ROOT: u8 = 0x02;
    /// Original file size, u64 LE (8 bytes) — mandatory.
    pub const ORIGINAL_SIZE: u8 = 0x03;
    /// Compressed payload size, u64 LE (8 bytes) — mandatory.
    pub const COMPRESSED_SIZE: u8 = 0x04;
    /// Block size identifier (1 byte) — mandatory.
    pub const BLOCK_SIZE_ID: u8 = 0x05;
    /// Merkle tree algorithm version (1 byte) — mandatory.
    /// Stored explicitly so future algorithm changes remain backward-compatible.
    pub const MERKLE_ALGO_ID: u8 = 0x06;
    /// Original filename, UTF-8 (≤ 255 bytes) — optional.
    pub const FILENAME: u8 = 0x10;
    /// Plaintext comment, UTF-8 (≤ 255 bytes) — optional.
    pub const COMMENT: u8 = 0x11;
    /// Creation timestamp, unix seconds u64 LE (8 bytes) — optional.
    pub const TIMESTAMP_SECS: u8 = 0x12;
}

/// Optional user-supplied metadata stored inside the ProtectedMetadata section.
#[derive(Default, Debug, Clone)]
pub struct EnvelopeMetadata {
    pub filename: Option<String>,
    pub comment: Option<String>,
    pub timestamp_secs: Option<u64>,
}

/// Parsed public header fields.
pub struct PublicHeader {
    pub compression_id: u8,
    pub header_total_size: u16,
    pub salt: [u8; 16],
    pub t_cost: u32,
    pub m_cost: u32,
    pub p_cost: u32,
    pub file_base_nonce: [u8; 24],
    pub kek_nonce: [u8; 12],
    pub hdr_cipher_id: u8,
    pub pld_cipher_id: u8,
}

/// All fields recovered from the header after decryption.
/// Combines the DEK from the WrappedDEK keyslot with fields from ProtectedMetadata.
pub struct EnvelopeContent {
    pub dek: [u8; 32],
    pub merkle_root: [u8; 32],
    pub original_size: u64,
    pub compressed_size: u64,
    pub block_size_id: u8,
    /// Merkle tree algorithm version — see [`MERKLE_V1`].
    pub merkle_algo_id: u8,
    pub filename: Option<String>,
    pub comment: Option<String>,
    pub timestamp_secs: Option<u64>,
}

impl EnvelopeContent {
    pub fn metadata(&self) -> EnvelopeMetadata {
        EnvelopeMetadata {
            filename: self.filename.clone(),
            comment: self.comment.clone(),
            timestamp_secs: self.timestamp_secs,
        }
    }
}

// ── TLV helpers ───────────────────────────────────────────────────────────────

fn tlv_push(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    debug_assert!(value.len() <= 255, "TLV value exceeds 255 bytes");
    buf.push(tag);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Serialize the ProtectedMetadata TLV.
/// The DEK is NOT included — it lives in the separate WrappedDEK keyslot.
pub fn serialize_meta_tlv(env: &EnvelopeContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_TLV_MANDATORY_PT_LEN + 32);
    tlv_push(&mut buf, tlv_tags::MERKLE_ROOT, &env.merkle_root);
    tlv_push(
        &mut buf,
        tlv_tags::ORIGINAL_SIZE,
        &env.original_size.to_le_bytes(),
    );
    tlv_push(
        &mut buf,
        tlv_tags::COMPRESSED_SIZE,
        &env.compressed_size.to_le_bytes(),
    );
    tlv_push(&mut buf, tlv_tags::BLOCK_SIZE_ID, &[env.block_size_id]);
    tlv_push(&mut buf, tlv_tags::MERKLE_ALGO_ID, &[env.merkle_algo_id]);
    if let Some(ref s) = env.filename {
        let b = s.as_bytes();
        if !b.is_empty() {
            tlv_push(&mut buf, tlv_tags::FILENAME, &b[..b.len().min(255)]);
        }
    }
    if let Some(ref s) = env.comment {
        let b = s.as_bytes();
        if !b.is_empty() {
            tlv_push(&mut buf, tlv_tags::COMMENT, &b[..b.len().min(255)]);
        }
    }
    if let Some(ts) = env.timestamp_secs {
        tlv_push(&mut buf, tlv_tags::TIMESTAMP_SECS, &ts.to_le_bytes());
    }
    buf
}

/// Parse the ProtectedMetadata TLV and combine with the DEK from the keyslot.
/// Mandatory fields missing → error. Unknown tags are skipped (forward compat).
/// Duplicate tags: first occurrence wins.
pub fn deserialize_meta_tlv(buf: &[u8], dek: [u8; 32]) -> Result<EnvelopeContent, CoreErr> {
    let mut merkle_root: Option<[u8; 32]> = None;
    let mut original_size: Option<u64> = None;
    let mut compressed_size: Option<u64> = None;
    let mut block_size_id: Option<u8> = None;
    let mut merkle_algo_id: Option<u8> = None;
    let mut filename: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut timestamp_secs: Option<u64> = None;

    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + 2 > buf.len() {
            return Err(CoreErr::DecryptFail("TLV: truncated at tag/len".into()));
        }
        let tag = buf[pos];
        let len = buf[pos + 1] as usize;
        pos += 2;
        if pos + len > buf.len() {
            return Err(CoreErr::DecryptFail("TLV: value overruns buffer".into()));
        }
        let val = &buf[pos..pos + len];
        pos += len;

        match tag {
            tlv_tags::MERKLE_ROOT if len == 32 && merkle_root.is_none() => {
                merkle_root = Some(val.try_into().unwrap());
            }
            tlv_tags::ORIGINAL_SIZE if len == 8 && original_size.is_none() => {
                original_size = Some(u64::from_le_bytes(val.try_into().unwrap()));
            }
            tlv_tags::COMPRESSED_SIZE if len == 8 && compressed_size.is_none() => {
                compressed_size = Some(u64::from_le_bytes(val.try_into().unwrap()));
            }
            tlv_tags::BLOCK_SIZE_ID if len == 1 && block_size_id.is_none() => {
                block_size_id = Some(val[0]);
            }
            tlv_tags::MERKLE_ALGO_ID if len == 1 && merkle_algo_id.is_none() => {
                merkle_algo_id = Some(val[0]);
            }
            tlv_tags::FILENAME if filename.is_none() => {
                filename = std::str::from_utf8(val).ok().map(str::to_owned);
            }
            tlv_tags::COMMENT if comment.is_none() => {
                comment = std::str::from_utf8(val).ok().map(str::to_owned);
            }
            tlv_tags::TIMESTAMP_SECS if len == 8 && timestamp_secs.is_none() => {
                timestamp_secs = Some(u64::from_le_bytes(val.try_into().unwrap()));
            }
            _ => {} // unknown tag or duplicate: skip (forward compat)
        }
    }

    let merkle_algo_id =
        merkle_algo_id.ok_or_else(|| CoreErr::DecryptFail("TLV: missing MerkleAlgoId".into()))?;
    if merkle_algo_id != MERKLE_V1 {
        return Err(CoreErr::DecryptFail(format!(
            "Unknown Merkle algorithm version: {merkle_algo_id:#x}"
        )));
    }

    Ok(EnvelopeContent {
        dek,
        merkle_root: merkle_root
            .ok_or_else(|| CoreErr::DecryptFail("TLV: missing MerkleRoot".into()))?,
        original_size: original_size
            .ok_or_else(|| CoreErr::DecryptFail("TLV: missing OriginalSize".into()))?,
        compressed_size: compressed_size
            .ok_or_else(|| CoreErr::DecryptFail("TLV: missing CompressedSize".into()))?,
        block_size_id: block_size_id
            .ok_or_else(|| CoreErr::DecryptFail("TLV: missing BlockSizeId".into()))?,
        merkle_algo_id,
        filename,
        comment,
        timestamp_secs,
    })
}

// ── Public header (pre-MAC) serialization ─────────────────────────────────────

pub fn serialize_pre_mac(hdr: &PublicHeader) -> [u8; PRE_MAC_LEN] {
    let mut buf = [0u8; PRE_MAC_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..6].copy_from_slice(&VERSION);
    buf[6] = KDF_ID_ARGON2ID;
    buf[7] = hdr.hdr_cipher_id;
    buf[8] = hdr.pld_cipher_id;
    buf[9] = hdr.compression_id;
    buf[10..12].copy_from_slice(&hdr.header_total_size.to_le_bytes());
    buf[12..28].copy_from_slice(&hdr.salt);
    buf[28..32].copy_from_slice(&hdr.t_cost.to_le_bytes());
    buf[32..36].copy_from_slice(&hdr.m_cost.to_le_bytes());
    buf[36..40].copy_from_slice(&hdr.p_cost.to_le_bytes());
    buf[40..64].copy_from_slice(&hdr.file_base_nonce);
    buf[64..76].copy_from_slice(&hdr.kek_nonce);
    buf
}

/// Derive the pre-authentication key using a cheap Argon2id pass.
///
/// The resulting key is used exclusively to verify the HeaderMAC before running
/// the expensive full KEK derivation.  Using Argon2id here (instead of a raw
/// HMAC over the password) ensures that an attacker who obtains the header
/// cannot exploit the MAC check as a fast offline brute-force oracle.
pub fn compute_prekey(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], CoreErr> {
    let params = Params::new(PREKEY_M_COST_KB, PREKEY_T_COST, PREKEY_P_COST, Some(32))
        .map_err(|_| CoreErr::Argon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CoreErr::Argon2Hash)?;
    Ok(key)
}

pub fn compute_header_mac(prekey: &[u8; 32], pre_mac_bytes: &[u8; PRE_MAC_LEN]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(prekey).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.finalize().into_bytes().into()
}

pub fn verify_header_mac(
    prekey: &[u8; 32],
    pre_mac_bytes: &[u8; PRE_MAC_LEN],
    expected_mac: &[u8; 32],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(prekey).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.verify_slice(expected_mac).is_ok()
}

// ── Header assembly / parsing ─────────────────────────────────────────────────

/// Build the complete header byte vector.
/// `hdr.header_total_size` must equal `PUB_HEADER_LEN + encrypted_envelope.len()`.
pub fn build_header_bytes(
    hdr: &PublicHeader,
    header_mac: &[u8; 32],
    encrypted_envelope: &[u8],
) -> Vec<u8> {
    let total = hdr.header_total_size as usize;
    debug_assert!(
        PUB_HEADER_LEN + encrypted_envelope.len() <= total,
        "envelope too large for declared header_total_size"
    );
    let mut buf = vec![0u8; total];
    let pre_mac = serialize_pre_mac(hdr);
    buf[..PRE_MAC_LEN].copy_from_slice(&pre_mac);
    buf[PRE_MAC_LEN..PUB_HEADER_LEN].copy_from_slice(header_mac);
    buf[PUB_HEADER_LEN..PUB_HEADER_LEN + encrypted_envelope.len()]
        .copy_from_slice(encrypted_envelope);
    buf
}

/// Parse a header byte slice of any valid length.
///
/// Returns `(PublicHeader, pre_mac_bytes, header_mac, enc_envelope_region)`.
/// `enc_envelope_region` = bytes `[PUB_HEADER_LEN .. header_total_size]`.
pub fn parse_header_bytes(bytes: &[u8]) -> Result<ParsedHeader, CoreErr> {
    if bytes.len() < PUB_HEADER_LEN {
        return Err(CoreErr::BadSignature);
    }
    if bytes[0..4] != MAGIC {
        return Err(CoreErr::BadSignature);
    }
    if bytes[4..6] != VERSION {
        return Err(CoreErr::BadHeaderVersion);
    }

    let pre_mac: [u8; PRE_MAC_LEN] = bytes[..PRE_MAC_LEN].try_into().expect("PRE_MAC_LEN");
    let header_mac: [u8; 32] = bytes[PRE_MAC_LEN..PUB_HEADER_LEN].try_into().expect("32");
    let header_total_size = u16::from_le_bytes([bytes[10], bytes[11]]);

    let hdr = PublicHeader {
        compression_id: bytes[9],
        header_total_size,
        salt: bytes[12..28].try_into().expect("16 bytes"),
        t_cost: u32::from_le_bytes(bytes[28..32].try_into().expect("4 bytes")),
        m_cost: u32::from_le_bytes(bytes[32..36].try_into().expect("4 bytes")),
        p_cost: u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes")),
        file_base_nonce: bytes[40..64].try_into().expect("24 bytes"),
        kek_nonce: bytes[64..76].try_into().expect("12 bytes"),
        hdr_cipher_id: bytes[7],
        pld_cipher_id: bytes[8],
    };

    let env_end = (header_total_size as usize).min(bytes.len());
    let enc_envelope = bytes[PUB_HEADER_LEN..env_end].to_vec();

    Ok((hdr, pre_mac, header_mac, enc_envelope))
}
