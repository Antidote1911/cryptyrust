// Arsenic V2 header layout (256 bytes total):
//
// 0x00-0x03  Magic        = "ARSN"          (4)  plaintext
// 0x04-0x05  Version      = 0x00 0x02       (2)  plaintext
// 0x06       KDF_ID       = 0x01 (Argon2id) (1)  plaintext
// 0x07       HdrCipher_ID = 0x02 (SerpGCM)  (1)  plaintext
// 0x08       PldCipher_ID = 0x03 (XChaCha)  (1)  plaintext
// 0x09       Compress_ID  = 0x00/0x01       (1)  plaintext
// 0x0A-0x0B  HdrTotalSize = 0x0100 (256)    (2)  plaintext  ← u16 LE
// 0x0C-0x1B  Salt                           (16) plaintext
// 0x1C-0x1F  t_cost                         (4)  plaintext  ← u32 LE
// 0x20-0x23  m_cost (KB)                    (4)  plaintext  ← u32 LE
// 0x24-0x27  p_cost                         (4)  plaintext  ← u32 LE
// 0x28-0x3F  FileBaseNonce                  (24) plaintext
// 0x40-0x4B  KekNonce                       (12) plaintext
// ── MAC coverage ends at 0x4B (76 bytes) ──
// 0x4C-0x6B  HeaderMAC                      (32) plaintext  ← HMAC-SHA256
// 0x6C-0xC2  EncryptedEnvelope              (97) Serpent-GCM
//              plaintext (81 B): DEK(32)+MerkleRoot(32)+OrigSize(8)+CompSize(8)+BlockID(1)
//              GCM tag (16 B)
// 0xC3-0xFF  Padding zeros                  (51)

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::errors::CoreErr;

type HmacSha256 = Hmac<Sha256>;
type ParsedHeader = (PublicHeader, [u8; PRE_MAC_LEN], [u8; 32], Vec<u8>);

pub const MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"
pub const VERSION: [u8; 2] = [0x00, 0x02];
pub const KDF_ID_ARGON2ID: u8 = 0x01;
pub const HDR_CIPHER_SERPENT_GCM: u8 = 0x02;
pub const PLD_CIPHER_XCHACHA20: u8 = 0x03;
pub const COMPRESS_NONE: u8 = 0x00;
pub const DEFAULT_HEADER_SIZE: u16 = 256;

/// Byte length of the public (pre-MAC) section (0x00..0x4B inclusive).
pub const PRE_MAC_LEN: usize = 0x4C; // 76
/// Byte length of the full public header including MAC (0x00..0x6B inclusive).
pub const PUB_HEADER_LEN: usize = 0x6C; // 108
/// Plaintext envelope size in bytes.
pub const ENVELOPE_PT_LEN: usize = 81; // DEK(32)+Root(32)+OrigSz(8)+CmpSz(8)+BlkID(1)
/// GCM tag size.
pub const GCM_TAG: usize = 16;
/// Encrypted envelope size.
pub const ENVELOPE_ENC_LEN: usize = ENVELOPE_PT_LEN + GCM_TAG; // 97
/// Total header size in bytes.
pub const TOTAL_HEADER_LEN: usize = DEFAULT_HEADER_SIZE as usize; // 256

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
}

/// Plaintext content of the encrypted envelope.
pub struct EnvelopeContent {
    pub dek: [u8; 32],
    pub merkle_root: [u8; 32],
    pub original_size: u64,
    pub compressed_size: u64,
    pub block_size_id: u8,
}

/// Serialize the 76-byte pre-MAC section of the public header.
pub fn serialize_pre_mac(hdr: &PublicHeader) -> [u8; PRE_MAC_LEN] {
    let mut buf = [0u8; PRE_MAC_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..6].copy_from_slice(&VERSION);
    buf[6] = KDF_ID_ARGON2ID;
    buf[7] = HDR_CIPHER_SERPENT_GCM;
    buf[8] = PLD_CIPHER_XCHACHA20;
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

/// PreKey = HMAC-SHA256(key=password, data=salt)
pub fn compute_prekey(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.finalize().into_bytes().into()
}

/// HeaderMAC = HMAC-SHA256(key=prekey, data=header[0x00..0x4C])
pub fn compute_header_mac(prekey: &[u8; 32], pre_mac_bytes: &[u8; PRE_MAC_LEN]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(prekey).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.finalize().into_bytes().into()
}

/// Constant-time MAC verification.
pub fn verify_header_mac(
    prekey: &[u8; 32],
    pre_mac_bytes: &[u8; PRE_MAC_LEN],
    expected_mac: &[u8; 32],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(prekey).expect("HMAC accepts any key length");
    mac.update(pre_mac_bytes);
    mac.verify_slice(expected_mac).is_ok()
}

/// Serialize the envelope plaintext (81 bytes).
pub fn serialize_envelope(env: &EnvelopeContent) -> [u8; ENVELOPE_PT_LEN] {
    let mut buf = [0u8; ENVELOPE_PT_LEN];
    buf[0..32].copy_from_slice(&env.dek);
    buf[32..64].copy_from_slice(&env.merkle_root);
    buf[64..72].copy_from_slice(&env.original_size.to_le_bytes());
    buf[72..80].copy_from_slice(&env.compressed_size.to_le_bytes());
    buf[80] = env.block_size_id;
    buf
}

/// Deserialize the envelope plaintext (81 bytes).
pub fn deserialize_envelope(buf: &[u8]) -> Result<EnvelopeContent, CoreErr> {
    if buf.len() < ENVELOPE_PT_LEN {
        return Err(CoreErr::DecryptFail("Envelope too short".into()));
    }
    let dek: [u8; 32] = buf[0..32]
        .try_into()
        .map_err(|_| CoreErr::DecryptFail("DEK".into()))?;
    let merkle_root: [u8; 32] = buf[32..64]
        .try_into()
        .map_err(|_| CoreErr::DecryptFail("Merkle".into()))?;
    let original_size = u64::from_le_bytes(
        buf[64..72]
            .try_into()
            .map_err(|_| CoreErr::DecryptFail("orig_size".into()))?,
    );
    let compressed_size = u64::from_le_bytes(
        buf[72..80]
            .try_into()
            .map_err(|_| CoreErr::DecryptFail("comp_size".into()))?,
    );
    let block_size_id = buf[80];
    Ok(EnvelopeContent {
        dek,
        merkle_root,
        original_size,
        compressed_size,
        block_size_id,
    })
}

/// Write the complete 256-byte header to `buf`.
pub fn build_header_bytes(
    hdr: &PublicHeader,
    header_mac: &[u8; 32],
    encrypted_envelope: &[u8],
) -> [u8; TOTAL_HEADER_LEN] {
    assert!(
        encrypted_envelope.len() == ENVELOPE_ENC_LEN,
        "envelope must be exactly {ENVELOPE_ENC_LEN} bytes"
    );
    let mut buf = [0u8; TOTAL_HEADER_LEN];
    let pre_mac = serialize_pre_mac(hdr);
    buf[..PRE_MAC_LEN].copy_from_slice(&pre_mac); // 0x00..0x4C
    buf[PRE_MAC_LEN..PUB_HEADER_LEN].copy_from_slice(header_mac); // 0x4C..0x6C
    buf[PUB_HEADER_LEN..PUB_HEADER_LEN + ENVELOPE_ENC_LEN].copy_from_slice(encrypted_envelope); // 0x6C..0xC3
                                                                                                // 0xC3..0x100 remain zero (padding)
    buf
}

/// Parse the 256-byte header bytes, returning the public header and the raw encrypted envelope.
pub fn parse_header_bytes(bytes: &[u8; TOTAL_HEADER_LEN]) -> Result<ParsedHeader, CoreErr> {
    // Check magic
    if bytes[0..4] != MAGIC {
        return Err(CoreErr::BadSignature);
    }
    if bytes[4..6] != VERSION {
        return Err(CoreErr::BadHeaderVersion);
    }

    let pre_mac: [u8; PRE_MAC_LEN] = bytes[..PRE_MAC_LEN]
        .try_into()
        .expect("slice is exactly PRE_MAC_LEN");

    let header_mac: [u8; 32] = bytes[PRE_MAC_LEN..PUB_HEADER_LEN]
        .try_into()
        .expect("32 bytes");

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
    };

    let enc_envelope = bytes[PUB_HEADER_LEN..PUB_HEADER_LEN + ENVELOPE_ENC_LEN].to_vec();

    Ok((hdr, pre_mac, header_mac, enc_envelope))
}
