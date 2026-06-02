use crate::errors::CoreErr;
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
// HeaderMAC: 32 bytes  (BLAKE3_keyed_hash(KEK, pre-MAC region))
// PUB_HEADER_LEN = 77 + 32 = 109

pub const PRE_MAC_LEN: usize = 0x4D; // 77
pub const PUB_HEADER_LEN: usize = 0x6D; // 109
pub const GCM_TAG: usize = 16;

// ── Keyslot constants ─────────────────────────────────────────────────────────

/// Symmetric WrappedDEK: AEAD(KEK, DEK) = 32 ciphertext + 16 tag = 48 bytes.
/// Only this section changes on a password rekey.
pub const WRAPPED_DEK_LEN: usize = 32 + GCM_TAG; // 48

// ── ML-KEM-768 keyslot (existing) ────────────────────────────────────────────
pub const ASYM_KEYSLOT_EPHEMERAL_X25519_LEN: usize = 32;
pub const ASYM_KEYSLOT_MLKEM_CT_LEN: usize = 1088;
pub const ASYM_KEYSLOT_KEK_NONCE_LEN: usize = 12;
/// ML-KEM-768 keyslot = 32 + 1088 + 12 + 48 = 1180 bytes.
pub const ASYM_KEYSLOT_LEN: usize =
    ASYM_KEYSLOT_EPHEMERAL_X25519_LEN + ASYM_KEYSLOT_MLKEM_CT_LEN
    + ASYM_KEYSLOT_KEK_NONCE_LEN + WRAPPED_DEK_LEN;

/// Number of ML-KEM-768 keyslots field (u32 LE).
pub const ASYM_COUNT_LEN: usize = 4;

// ── ML-KEM-1024 keyslot (NIST Level 5) ───────────────────────────────────────
pub const ASYM_1024_KEYSLOT_MLKEM_CT_LEN: usize = 1568;
/// ML-KEM-1024 keyslot = 32 + 1568 + 12 + 48 = 1660 bytes.
pub const ASYM_1024_KEYSLOT_LEN: usize =
    ASYM_KEYSLOT_EPHEMERAL_X25519_LEN + ASYM_1024_KEYSLOT_MLKEM_CT_LEN
    + ASYM_KEYSLOT_KEK_NONCE_LEN + WRAPPED_DEK_LEN;

/// Number of ML-KEM-1024 keyslots field (u32 LE).
pub const ASYM_1024_COUNT_LEN: usize = 4;

// ── ML-DSA-65 signature region (optional, at end of header) ──────────────────
/// Byte marker: 0x00 = no signature, 0x01 = ML-DSA-65 signature present.
pub const SIG_PRESENT_LEN: usize = 1;
/// ML-DSA-65 verifying key size.
pub const MLDSA_VERIFYING_KEY_LEN: usize = 1952;
/// ML-DSA-65 signature size (NIST FIPS 204).
pub const MLDSA_SIGNATURE_LEN: usize = 3309;

pub const MAX_ASYM_KEYSLOTS: usize = 256;

pub const MERKLE_V1: u8 = 0x01;
pub const SIG_PRESENT_NONE: u8 = 0x00;
pub const SIG_PRESENT_MLDSA65: u8 = 0x01;
pub const SENDER_PRESENT_LEN: usize = 1; // sender_present byte

pub const META_TLV_MANDATORY_PT_LEN: usize = 50;

/// Minimum total header size (0 keyslots, no signature, no sender, no optional metadata):
///   PUB_HEADER_LEN(109) + WRAPPED_DEK_LEN(48) + ASYM_COUNT_LEN(4)
///   + ASYM_1024_COUNT_LEN(4) + SIG_PRESENT_LEN(1) + SENDER_PRESENT_LEN(1)
///   + META_TLV_MANDATORY_PT_LEN(50) + GCM_TAG(16) = 233
pub const MIN_HEADER_TOTAL_SIZE: usize =
    PUB_HEADER_LEN + WRAPPED_DEK_LEN + ASYM_COUNT_LEN + ASYM_1024_COUNT_LEN
    + META_TLV_MANDATORY_PT_LEN + GCM_TAG + SIG_PRESENT_LEN + SENDER_PRESENT_LEN;

// ── TLV tag identifiers ───────────────────────────────────────────────────────

pub mod tlv_tags {
    pub const MERKLE_ROOT: u8 = 0x02;
    pub const ORIGINAL_SIZE: u8 = 0x03;
    // 0x04 (CompressedSize) removed — always equalled OriginalSize (no compression).
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

/// Sender identity stored in the **public** header (after the signature region).
///
/// Readable without decryption — the recipient can extract it and add the sender
/// as a contact, then encrypt back, without any separate .pubkey file exchange.
/// The public keys are already non-secret; only the sender name is revealed.
#[derive(Clone, Debug)]
pub struct SenderInfo {
    pub name: String,
    pub x25519_pk: [u8; 32],
    pub mlkem_pk: [u8; 1184],
}

/// Byte marker for the sender region: 0x00 = none, 0x01 = present.
pub const SENDER_PRESENT_NONE: u8 = 0x00;
pub const SENDER_PRESENT: u8 = 0x01;

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

/// One hybrid (X25519 + ML-KEM-1024) keyslot — 1660 bytes on disk.
/// Same structure as `HybridKeyslot` but with a 1568-byte ML-KEM-1024 ciphertext.
#[derive(Clone)]
pub struct HybridKeyslot1024 {
    pub ephemeral_x25519: [u8; 32],
    pub mlkem_ct: [u8; ASYM_1024_KEYSLOT_MLKEM_CT_LEN],
    pub kek_nonce: [u8; 12],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

impl HybridKeyslot1024 {
    pub fn to_bytes(&self) -> [u8; ASYM_1024_KEYSLOT_LEN] {
        let mut buf = [0u8; ASYM_1024_KEYSLOT_LEN];
        let mut off = 0;
        buf[off..off+32].copy_from_slice(&self.ephemeral_x25519); off += 32;
        buf[off..off+ASYM_1024_KEYSLOT_MLKEM_CT_LEN].copy_from_slice(&self.mlkem_ct); off += ASYM_1024_KEYSLOT_MLKEM_CT_LEN;
        buf[off..off+12].copy_from_slice(&self.kek_nonce); off += 12;
        buf[off..off+WRAPPED_DEK_LEN].copy_from_slice(&self.wrapped_dek);
        buf
    }

    pub fn from_bytes(bytes: &[u8; ASYM_1024_KEYSLOT_LEN]) -> Self {
        let mut off = 0;
        let ephemeral_x25519: [u8; 32] = bytes[off..off+32].try_into().unwrap(); off += 32;
        let mlkem_ct: [u8; ASYM_1024_KEYSLOT_MLKEM_CT_LEN] = bytes[off..off+ASYM_1024_KEYSLOT_MLKEM_CT_LEN].try_into().unwrap(); off += ASYM_1024_KEYSLOT_MLKEM_CT_LEN;
        let kek_nonce: [u8; 12] = bytes[off..off+12].try_into().unwrap(); off += 12;
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = bytes[off..off+WRAPPED_DEK_LEN].try_into().unwrap();
        Self { ephemeral_x25519, mlkem_ct, kek_nonce, wrapped_dek }
    }
}

/// Optional ML-DSA-65 signature attached at the end of the header.
/// `sig_msg` = pre_mac[77] (authenticated header parameters).
#[derive(Clone)]
pub struct MlDsaSignature {
    /// ML-DSA-65 verifying (public) key — 1952 bytes.
    pub verifying_key: Box<[u8; MLDSA_VERIFYING_KEY_LEN]>,
    /// ML-DSA-65 signature — 3293 bytes.
    pub signature: Box<[u8; MLDSA_SIGNATURE_LEN]>,
}

/// Parsed envelope region (post-MAC).
///
/// Layout:  sym_wrapped_dek(48) | asym_768_count(4) | keyslots_768(1180×N)
///        | asym_1024_count(4)  | keyslots_1024(1660×M)
///        | protected_meta(var) | sig_present(1) | [sig_region]
pub struct ParsedEnvelope {
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub hybrid_keyslots: Vec<HybridKeyslot>,
    pub hybrid_keyslots_1024: Vec<HybridKeyslot1024>,
    pub protected_meta: Vec<u8>,
    pub mldsa_sig: Option<MlDsaSignature>,
    /// Sender identity — stored in the public header, readable without decryption.
    pub sender: Option<SenderInfo>,
}

// ── TLV helpers ───────────────────────────────────────────────────────────────

/// Push a TLV entry.  For values ≤ 254 bytes the length is one byte.
/// For values ≥ 255 bytes the length byte is 0xFF followed by four
/// little-endian bytes (extended-length encoding).
fn tlv_push(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    buf.push(tag);
    if value.len() < 0xFF {
        buf.push(value.len() as u8);
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    }
    buf.extend_from_slice(value);
}

pub fn serialize_meta_tlv(env: &EnvelopeContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_TLV_MANDATORY_PT_LEN + 32);
    tlv_push(&mut buf, tlv_tags::MERKLE_ROOT, &env.merkle_root);
    tlv_push(&mut buf, tlv_tags::ORIGINAL_SIZE, &env.original_size.to_le_bytes());
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
        let tag = buf[pos]; pos += 1;
        // Extended-length encoding: 0xFF byte followed by 4-byte LE length.
        let len = if buf[pos] == 0xFF {
            pos += 1;
            if pos + 4 > buf.len() {
                return Err(CoreErr::DecryptFail("TLV: truncated extended length".into()));
            }
            let l = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            l
        } else {
            let l = buf[pos] as usize;
            pos += 1;
            l
        };
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
            _ => {} // unknown or obsolete tags silently ignored
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
        block_size_id: block_size_id
            .ok_or_else(|| CoreErr::DecryptFail("TLV: missing BlockSizeId".into()))?,
        merkle_algo_id,
        filename,
        comment,
        timestamp_secs,
    })
}

// ── Envelope region helpers ───────────────────────────────────────────────────

/// Parse the envelope region (post-MAC).
///
/// Layout: wrapped_dek(48) | count_768(4) | keyslots_768(1180×N)
///        | count_1024(4)  | keyslots_1024(1660×M)
///        | protected_meta(var) | sig_present(1) | [mldsa_vk(1952) | mldsa_sig(3293)]
pub fn parse_envelope(enc_region: &[u8]) -> Result<ParsedEnvelope, CoreErr> {
    let min = WRAPPED_DEK_LEN + ASYM_COUNT_LEN + ASYM_1024_COUNT_LEN + SIG_PRESENT_LEN;
    if enc_region.len() < min {
        return Err(CoreErr::DecryptFail("Envelope region too short".into()));
    }

    let wrapped_dek: [u8; WRAPPED_DEK_LEN] = enc_region[..WRAPPED_DEK_LEN].try_into().unwrap();
    let mut pos = WRAPPED_DEK_LEN;

    // ML-KEM-768 keyslots
    let count_768 = u32::from_le_bytes(enc_region[pos..pos+4].try_into().unwrap()) as usize;
    pos += 4;
    if count_768 > MAX_ASYM_KEYSLOTS {
        return Err(CoreErr::DecryptFail(format!("too many 768 keyslots: {count_768}")));
    }
    let end_768 = pos.checked_add(count_768 * ASYM_KEYSLOT_LEN)
        .ok_or_else(|| CoreErr::DecryptFail("768 keyslot overflow".into()))?;
    if enc_region.len() < end_768 {
        return Err(CoreErr::DecryptFail("Envelope too short for 768 keyslots".into()));
    }
    let mut hybrid_keyslots = Vec::with_capacity(count_768);
    for i in 0..count_768 {
        let s = pos + i * ASYM_KEYSLOT_LEN;
        hybrid_keyslots.push(HybridKeyslot::from_bytes(enc_region[s..s+ASYM_KEYSLOT_LEN].try_into().unwrap()));
    }
    pos = end_768;

    // ML-KEM-1024 keyslots
    let count_1024 = u32::from_le_bytes(enc_region[pos..pos+4].try_into().unwrap()) as usize;
    pos += 4;
    if count_1024 > MAX_ASYM_KEYSLOTS {
        return Err(CoreErr::DecryptFail(format!("too many 1024 keyslots: {count_1024}")));
    }
    let end_1024 = pos.checked_add(count_1024 * ASYM_1024_KEYSLOT_LEN)
        .ok_or_else(|| CoreErr::DecryptFail("1024 keyslot overflow".into()))?;
    if enc_region.len() < end_1024 {
        return Err(CoreErr::DecryptFail("Envelope too short for 1024 keyslots".into()));
    }
    let mut hybrid_keyslots_1024 = Vec::with_capacity(count_1024);
    for i in 0..count_1024 {
        let s = pos + i * ASYM_1024_KEYSLOT_LEN;
        hybrid_keyslots_1024.push(HybridKeyslot1024::from_bytes(enc_region[s..s+ASYM_1024_KEYSLOT_LEN].try_into().unwrap()));
    }
    pos = end_1024;

    // protected_meta ends SIG_PRESENT_LEN bytes before the end (or at sig_region start)
    // We locate the sig_present byte by counting backward from the end of the
    // region, after protected_meta. The sig_present is at the end of the region
    // (last 1 byte, or last 1+1952+3293 bytes if signed).
    // We scan forward: everything until the last SIG_PRESENT_LEN byte(s) is protected_meta.
    // The sig_present byte is always the LAST byte of the non-protected-meta section.
    // But we need to know where protected_meta ends. Since the caller gives us the full
    // enc_region (from PUB_HEADER_LEN to header_total_size), we determine sig length
    // from the sig_present byte located appropriately.

    // Remaining bytes after 1024 keyslots
    let remaining = &enc_region[pos..];

    // The sig_present byte comes AFTER protected_meta, before the optional sig data.
    // Layout from the end of `remaining` (inner → outer):
    //   [sender_region] sig_present[1] [sig_data?]
    // We scan from the end: first peel off the sender region, then the signature.

    // ── Sender region (outermost, at the very end) ──
    // Format: sender_present[1] [name_len[2 LE] + name[N] + x25519[32] + mlkem[1184]]
    let sender;
    let after_sender;
    let sender_min = 1usize; // just the sender_present byte
    if remaining.len() < sender_min {
        return Err(CoreErr::DecryptFail("Envelope missing sender_present byte".into()));
    }
    let last = remaining[remaining.len() - 1];
    if last == SENDER_PRESENT {
        // Parse sender: [name_len[2 LE] + name[N] + x25519[32] + mlkem[1184]] + SENDER_PRESENT
        let fixed_tail = 1 + 2 + 32 + 1184; // sender_present + name_len + x25519 + mlkem
        if remaining.len() < fixed_tail {
            return Err(CoreErr::DecryptFail("Envelope sender region too short".into()));
        }
        let sp = remaining.len() - 1; // index of sender_present byte
        let mlkem_start = sp - 1184;
        let x25519_start = mlkem_start - 32;
        let name_len_start = x25519_start - 2;
        let name_len = u16::from_le_bytes(remaining[name_len_start..name_len_start+2].try_into().unwrap()) as usize;
        if name_len_start < name_len {
            return Err(CoreErr::DecryptFail("Envelope sender name overruns".into()));
        }
        let name_start = name_len_start - name_len;
        let name = std::str::from_utf8(&remaining[name_start..name_start+name_len])
            .unwrap_or("").to_string();
        let x25519_pk: [u8; 32] = remaining[x25519_start..x25519_start+32].try_into().unwrap();
        let mlkem_pk: [u8; 1184] = remaining[mlkem_start..mlkem_start+1184].try_into().unwrap();
        sender = Some(SenderInfo { name, x25519_pk, mlkem_pk });
        after_sender = &remaining[..name_start];
    } else {
        // SENDER_PRESENT_NONE: just the one byte
        sender = None;
        after_sender = &remaining[..remaining.len() - 1];
    }

    // ── Signature region ──
    let mldsa_sig;
    let protected_meta_slice;
    let sig_total = SIG_PRESENT_LEN + MLDSA_VERIFYING_KEY_LEN + MLDSA_SIGNATURE_LEN;
    if after_sender.len() >= sig_total && after_sender[after_sender.len() - sig_total] == SIG_PRESENT_MLDSA65 {
        let sig_start = after_sender.len() - sig_total;
        protected_meta_slice = &after_sender[..sig_start];
        let vk_start = sig_start + SIG_PRESENT_LEN;
        let s_start = vk_start + MLDSA_VERIFYING_KEY_LEN;
        let vk: Box<[u8; MLDSA_VERIFYING_KEY_LEN]> =
            Box::new(after_sender[vk_start..vk_start+MLDSA_VERIFYING_KEY_LEN].try_into().unwrap());
        let sig: Box<[u8; MLDSA_SIGNATURE_LEN]> =
            Box::new(after_sender[s_start..s_start+MLDSA_SIGNATURE_LEN].try_into().unwrap());
        mldsa_sig = Some(MlDsaSignature { verifying_key: vk, signature: sig });
    } else {
        if after_sender.is_empty() {
            return Err(CoreErr::DecryptFail("Envelope missing sig_present byte".into()));
        }
        protected_meta_slice = &after_sender[..after_sender.len() - SIG_PRESENT_LEN];
        mldsa_sig = None;
    }

    Ok(ParsedEnvelope {
        wrapped_dek,
        hybrid_keyslots,
        hybrid_keyslots_1024,
        protected_meta: protected_meta_slice.to_vec(),
        mldsa_sig,
        sender,
    })
}

/// Serialize the envelope region.
pub fn build_envelope_region(
    wrapped_dek: &[u8; WRAPPED_DEK_LEN],
    hybrid_keyslots: &[HybridKeyslot],
    hybrid_keyslots_1024: &[HybridKeyslot1024],
    protected_meta: &[u8],
    mldsa_sig: Option<&MlDsaSignature>,
    sender: Option<&SenderInfo>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(wrapped_dek);
    buf.extend_from_slice(&(hybrid_keyslots.len() as u32).to_le_bytes());
    for slot in hybrid_keyslots { buf.extend_from_slice(&slot.to_bytes()); }
    buf.extend_from_slice(&(hybrid_keyslots_1024.len() as u32).to_le_bytes());
    for slot in hybrid_keyslots_1024 { buf.extend_from_slice(&slot.to_bytes()); }
    buf.extend_from_slice(protected_meta);
    // Signature region
    if let Some(sig) = mldsa_sig {
        buf.push(SIG_PRESENT_MLDSA65);
        buf.extend_from_slice(sig.verifying_key.as_slice());
        buf.extend_from_slice(sig.signature.as_slice());
    } else {
        buf.push(SIG_PRESENT_NONE);
    }
    // Sender region (public — readable without decryption)
    if let Some(s) = sender {
        let name_bytes = s.name.as_bytes();
        let name_len = name_bytes.len().min(255) as u16;
        buf.extend_from_slice(&name_bytes[..name_len as usize]);
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&s.x25519_pk);
        buf.extend_from_slice(&s.mlkem_pk);
        buf.push(SENDER_PRESENT);
    } else {
        buf.push(SENDER_PRESENT_NONE);
    }
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

/// Compute HeaderMAC = BLAKE3_keyed_hash(KEK, pre_mac).
///
/// BLAKE3 is used throughout arsenic for all internal derivations; using it here
/// replaces the former HMAC-SHA256 and removes the sha2/hmac crates entirely.
pub fn compute_header_mac(kek: &[u8; 32], pre_mac_bytes: &[u8; PRE_MAC_LEN]) -> [u8; 32] {
    *blake3::keyed_hash(kek, pre_mac_bytes.as_slice()).as_bytes()
}

/// Verify HeaderMAC in constant time.
pub fn verify_header_mac(
    kek: &[u8; 32],
    pre_mac_bytes: &[u8; PRE_MAC_LEN],
    expected_mac: &[u8; 32],
) -> bool {
    // blake3::Hash::eq is documented as constant-time.
    blake3::keyed_hash(kek, pre_mac_bytes.as_slice()) == blake3::Hash::from(*expected_mac)
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
