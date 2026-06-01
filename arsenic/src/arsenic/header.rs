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

/// Hard upper bounds on Argon2id parameters accepted during decryption.
/// Reject headers with forged extreme values before running any KDF.
pub const MAX_T_COST: u32 = 64;
pub const MAX_P_COST: u32 = 16;

// ── Header layout ─────────────────────────────────────────────────────────────
//
// Public section (pre-MAC) — 77 bytes:
//   0x00–0x03   4   Magic
//   0x04–0x05   2   Version (00 01)
//   0x06        1   KDF ID
//   0x07        1   Header cipher ID
//   0x08        1   Payload cipher ID
//   0x09–0x0C   4   header_total_size (u32 LE)
//   0x0D–0x1C  16   Argon2id salt
//   0x1D–0x20   4   t_cost
//   0x21–0x24   4   m_cost
//   0x25–0x28   4   p_cost
//   0x29–0x40  24   file_base_nonce
//   0x41–0x4C  12   kek_nonce (for primary symmetric keyslot)
//
// HeaderMAC: 32 bytes  (HMAC-SHA256 of pre-MAC region)
// PUB_HEADER_LEN = 77 + 32 = 109

pub const PRE_MAC_LEN: usize = 0x4D; // 77
pub const PUB_HEADER_LEN: usize = 0x6D; // 109
pub const GCM_TAG: usize = 16;

// ── Keyslot constants ─────────────────────────────────────────────────────────

/// Symmetric WrappedDEK: AEAD(KEK, DEK) = 32 ciphertext + 16 tag = 48 bytes.
/// Only this section changes on a password rekey.
pub const WRAPPED_DEK_LEN: usize = 32 + GCM_TAG; // 48

/// Hybrid keyslot (X25519 + ML-KEM-768):
///   ephemeral_x25519_pk[32] + mlkem_ciphertext[1088] + kek_nonce[12] + wrapped_dek[48]
///   = 1180 bytes
pub const ASYM_KEYSLOT_EPHEMERAL_X25519_LEN: usize = 32;
pub const ASYM_KEYSLOT_MLKEM_CT_LEN: usize = 1088;
pub const ASYM_KEYSLOT_KEK_NONCE_LEN: usize = 12;
pub const ASYM_KEYSLOT_LEN: usize =
    ASYM_KEYSLOT_EPHEMERAL_X25519_LEN   // 32
    + ASYM_KEYSLOT_MLKEM_CT_LEN        // 1088
    + ASYM_KEYSLOT_KEK_NONCE_LEN       // 12
    + WRAPPED_DEK_LEN;                  // 48  → total 1180

/// Number of asymmetric keyslots is stored as a u32 LE.
pub const ASYM_COUNT_LEN: usize = 4;

/// Hard limit on the number of hybrid keyslots accepted during parsing.
///
/// 1 keyslot = 1180 bytes.  256 keyslots × 1180 ≈ 295 KiB — well within
/// MAX_HEADER_TOTAL_SIZE (64 MiB).  For a DoS attacker: 256 × (ECDH + ML-KEM
/// decaps) ≈ 256 × ~100 µs = ~25 ms per private key.  Realistic maximum for
/// any organisation use case is in the tens.
pub const MAX_ASYM_KEYSLOTS: usize = 256;

pub const MERKLE_V1: u8 = 0x01;

pub const META_TLV_MANDATORY_PT_LEN: usize = 60;

/// Minimum total header size (0 asymmetric keyslots, no optional metadata):
///   PUB_HEADER_LEN(110) + WRAPPED_DEK_LEN(48) + ASYM_COUNT_LEN(4)
///   + META_TLV_MANDATORY_PT_LEN(60) + GCM_TAG(16) = 238
pub const MIN_HEADER_TOTAL_SIZE: usize =
    PUB_HEADER_LEN + WRAPPED_DEK_LEN + ASYM_COUNT_LEN + META_TLV_MANDATORY_PT_LEN + GCM_TAG;

// ── TLV tag identifiers ───────────────────────────────────────────────────────

pub mod tlv_tags {
    pub const MERKLE_ROOT: u8 = 0x02;
    pub const ORIGINAL_SIZE: u8 = 0x03;
    pub const COMPRESSED_SIZE: u8 = 0x04;
    pub const BLOCK_SIZE_ID: u8 = 0x05;
    pub const MERKLE_ALGO_ID: u8 = 0x06;
    pub const FILENAME: u8 = 0x10;
    pub const COMMENT: u8 = 0x11;
    pub const TIMESTAMP_SECS: u8 = 0x12;
}

// ── Structs ───────────────────────────────────────────────────────────────────

#[derive(Default, Debug, Clone)]
pub struct EnvelopeMetadata {
    pub filename: Option<String>,
    pub comment: Option<String>,
    pub timestamp_secs: Option<u64>,
}

/// One hybrid (X25519 + ML-KEM-768) keyslot — 1180 bytes on disk.
///
/// Encryption:
///   1. Fresh X25519 ephemeral keypair → `ss_x25519 = ECDH(ephemeral_sk, recipient_x25519_pk)`
///   2. ML-KEM-768 encapsulation      → `(mlkem_ct, ss_mlkem) = Encaps(recipient_mlkem_ek)`
///   3. Hybrid wrapping key           → `wrapping_key = BLAKE3_derive_key(
///        "Arsenic Hybrid KEM", ephemeral_x25519_pk || mlkem_ct || ss_x25519 || ss_mlkem)`
///   4. Wrap DEK                       → `wrapped_dek = AEAD(wrapping_key, kek_nonce, DEK)`
///
/// Decryption reverses steps 3-1 using the recipient's X25519 and ML-KEM secret keys.
#[derive(Clone)]
pub struct HybridKeyslot {
    /// X25519 ephemeral public key (32 bytes).
    pub ephemeral_x25519: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub mlkem_ct: [u8; ASYM_KEYSLOT_MLKEM_CT_LEN],
    /// Nonce for AEAD wrapping of the DEK.
    pub kek_nonce: [u8; 12],
    /// AEAD-encrypted DEK.
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

impl HybridKeyslot {
    pub fn to_bytes(&self) -> [u8; ASYM_KEYSLOT_LEN] {
        let mut buf = [0u8; ASYM_KEYSLOT_LEN];
        let mut off = 0;
        buf[off..off + 32].copy_from_slice(&self.ephemeral_x25519); off += 32;
        buf[off..off + ASYM_KEYSLOT_MLKEM_CT_LEN].copy_from_slice(&self.mlkem_ct); off += ASYM_KEYSLOT_MLKEM_CT_LEN;
        buf[off..off + 12].copy_from_slice(&self.kek_nonce); off += 12;
        buf[off..off + WRAPPED_DEK_LEN].copy_from_slice(&self.wrapped_dek);
        buf
    }

    pub fn from_bytes(bytes: &[u8; ASYM_KEYSLOT_LEN]) -> Self {
        let mut off = 0;
        let ephemeral_x25519: [u8; 32] = bytes[off..off + 32].try_into().unwrap(); off += 32;
        let mlkem_ct: [u8; ASYM_KEYSLOT_MLKEM_CT_LEN] = bytes[off..off + ASYM_KEYSLOT_MLKEM_CT_LEN].try_into().unwrap(); off += ASYM_KEYSLOT_MLKEM_CT_LEN;
        let kek_nonce: [u8; 12] = bytes[off..off + 12].try_into().unwrap(); off += 12;
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = bytes[off..off + WRAPPED_DEK_LEN].try_into().unwrap();
        Self { ephemeral_x25519, mlkem_ct, kek_nonce, wrapped_dek }
    }
}

pub struct PublicHeader {
    pub header_total_size: u32,
    pub salt: [u8; 16],
    pub t_cost: u32,
    pub m_cost: u32,
    pub p_cost: u32,
    pub file_base_nonce: [u8; 24],
    pub kek_nonce: [u8; 12],
    pub hdr_cipher_id: u8,
    pub pld_cipher_id: u8,
}

pub struct EnvelopeContent {
    pub dek: [u8; 32],
    pub merkle_root: [u8; 32],
    pub original_size: u64,
    pub compressed_size: u64,
    pub block_size_id: u8,
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

/// Parsed envelope region (post-MAC).
///
/// Layout:  sym_wrapped_dek(48) | asym_count(4) | keyslots(1180×N) | protected_meta(var)
pub struct ParsedEnvelope {
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub hybrid_keyslots: Vec<HybridKeyslot>,
    pub protected_meta: Vec<u8>,
}

// ── TLV helpers ───────────────────────────────────────────────────────────────

fn tlv_push(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    debug_assert!(value.len() <= 255, "TLV value exceeds 255 bytes");
    buf.push(tag);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

pub fn serialize_meta_tlv(env: &EnvelopeContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_TLV_MANDATORY_PT_LEN + 32);
    tlv_push(&mut buf, tlv_tags::MERKLE_ROOT, &env.merkle_root);
    tlv_push(&mut buf, tlv_tags::ORIGINAL_SIZE, &env.original_size.to_le_bytes());
    tlv_push(&mut buf, tlv_tags::COMPRESSED_SIZE, &env.compressed_size.to_le_bytes());
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
            _ => {}
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

// ── Envelope region helpers ───────────────────────────────────────────────────

/// Parse the envelope region (post-MAC) into its three components:
///   sym_wrapped_dek(48) || asym_count(4) || keyslots(1180×N) || protected_meta
pub fn parse_envelope(enc_region: &[u8]) -> Result<ParsedEnvelope, CoreErr> {
    let min = WRAPPED_DEK_LEN + ASYM_COUNT_LEN;
    if enc_region.len() < min {
        return Err(CoreErr::DecryptFail("Envelope region too short".into()));
    }

    let wrapped_dek: [u8; WRAPPED_DEK_LEN] =
        enc_region[..WRAPPED_DEK_LEN].try_into().unwrap();

    let asym_count = u32::from_le_bytes(
        enc_region[WRAPPED_DEK_LEN..WRAPPED_DEK_LEN + 4].try_into().unwrap(),
    ) as usize;

    if asym_count > MAX_ASYM_KEYSLOTS {
        return Err(CoreErr::DecryptFail(format!(
            "too many hybrid keyslots: {asym_count} (max {MAX_ASYM_KEYSLOTS})"
        )));
    }

    let keyslots_start = WRAPPED_DEK_LEN + ASYM_COUNT_LEN;
    let keyslots_end = keyslots_start
        .checked_add(asym_count * ASYM_KEYSLOT_LEN)
        .ok_or_else(|| CoreErr::DecryptFail("Hybrid keyslot count overflow".into()))?;

    if enc_region.len() < keyslots_end {
        return Err(CoreErr::DecryptFail(
            "Envelope too short for declared hybrid keyslots".into(),
        ));
    }

    let mut hybrid_keyslots = Vec::with_capacity(asym_count);
    for i in 0..asym_count {
        let start = keyslots_start + i * ASYM_KEYSLOT_LEN;
        let slot: &[u8; ASYM_KEYSLOT_LEN] =
            enc_region[start..start + ASYM_KEYSLOT_LEN].try_into().unwrap();
        hybrid_keyslots.push(HybridKeyslot::from_bytes(slot));
    }

    let protected_meta = enc_region[keyslots_end..].to_vec();

    Ok(ParsedEnvelope { wrapped_dek, hybrid_keyslots, protected_meta })
}

/// Serialize the envelope region from its three components.
pub fn build_envelope_region(
    wrapped_dek: &[u8; WRAPPED_DEK_LEN],
    hybrid_keyslots: &[HybridKeyslot],
    protected_meta: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        WRAPPED_DEK_LEN + ASYM_COUNT_LEN
        + hybrid_keyslots.len() * ASYM_KEYSLOT_LEN
        + protected_meta.len(),
    );
    buf.extend_from_slice(wrapped_dek);
    buf.extend_from_slice(&(hybrid_keyslots.len() as u32).to_le_bytes());
    for slot in hybrid_keyslots {
        buf.extend_from_slice(&slot.to_bytes());
    }
    buf.extend_from_slice(protected_meta);
    buf
}

// ── Public header serialization ───────────────────────────────────────────────

pub fn serialize_pre_mac(hdr: &PublicHeader) -> [u8; PRE_MAC_LEN] {
    let mut buf = [0u8; PRE_MAC_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..6].copy_from_slice(&VERSION);
    buf[6] = KDF_ID_ARGON2ID;
    buf[7] = hdr.hdr_cipher_id;
    buf[8] = hdr.pld_cipher_id;
    buf[9..13].copy_from_slice(&hdr.header_total_size.to_le_bytes());
    buf[13..29].copy_from_slice(&hdr.salt);
    buf[29..33].copy_from_slice(&hdr.t_cost.to_le_bytes());
    buf[33..37].copy_from_slice(&hdr.m_cost.to_le_bytes());
    buf[37..41].copy_from_slice(&hdr.p_cost.to_le_bytes());
    buf[41..65].copy_from_slice(&hdr.file_base_nonce);
    buf[65..77].copy_from_slice(&hdr.kek_nonce);
    buf
}

pub fn compute_header_mac(kek: &[u8; 32], pre_mac_bytes: &[u8; PRE_MAC_LEN]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(kek).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.finalize().into_bytes().into()
}

pub fn verify_header_mac(
    kek: &[u8; 32],
    pre_mac_bytes: &[u8; PRE_MAC_LEN],
    expected_mac: &[u8; 32],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(kek).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.verify_slice(expected_mac).is_ok()
}

// ── Header assembly / parsing ─────────────────────────────────────────────────

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
    let header_total_size =
        u32::from_le_bytes(bytes[9..13].try_into().expect("4 bytes for u32 header_total_size"));

    let hdr = PublicHeader {
        header_total_size,
        salt: bytes[13..29].try_into().expect("16 bytes"),
        t_cost: u32::from_le_bytes(bytes[29..33].try_into().expect("4 bytes")),
        m_cost: u32::from_le_bytes(bytes[33..37].try_into().expect("4 bytes")),
        p_cost: u32::from_le_bytes(bytes[37..41].try_into().expect("4 bytes")),
        file_base_nonce: bytes[41..65].try_into().expect("24 bytes"),
        kek_nonce: bytes[65..77].try_into().expect("12 bytes"),
        hdr_cipher_id: bytes[7],
        pld_cipher_id: bytes[8],
    };

    let env_end = (header_total_size as usize).min(bytes.len());
    let enc_envelope = bytes[PUB_HEADER_LEN..env_end].to_vec();

    Ok((hdr, pre_mac, header_mac, enc_envelope))
}
