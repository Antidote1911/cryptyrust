pub mod bench;
mod cipher_dispatch;
mod crypto;
pub(crate) mod header;
pub(crate) mod hybrid_kem;

pub use crypto::{
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic, find_decrypting_key,
    list_recipients, rekey_arsenic,
    build_header_with_added_recipient, build_header_with_removed_recipient,
};

use crate::arsenic::hybrid_kem::EK_LEN as MLKEM_EK_LEN;
pub use header::{HybridKeyslot, EnvelopeMetadata, MIN_HEADER_TOTAL_SIZE, WRAPPED_DEK_LEN};

// Safety limits (DoS protection).
// u32 header_total_size allows headers up to 64 MiB, supporting ~700 000 recipients.
pub const MAX_ARGON2_RAM_KB: u32 = 8 * 1024 * 1024; // 8 GB
pub const MAX_HEADER_TOTAL_SIZE: u32 = 64 * 1024 * 1024; // 64 MiB

// Block size constants
pub const BLOCK_SIZE_4MB: usize = 4 * 1024 * 1024;
pub const BLOCK_SIZE_32MB: usize = 32 * 1024 * 1024;
pub const LARGE_FILE_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

pub const BLOCK_ID_4MB: u8 = 0x01;
pub const BLOCK_ID_32MB: u8 = 0x02;

/// A hybrid X25519 + ML-KEM-768 recipient public key.
///
/// Both components are derived from the same seed stored in the recipient's
/// `.key` file, so contacts only need to share one combined key string.
#[derive(Clone, Debug)]
pub struct HybridRecipient {
    /// X25519 public key — 32 bytes.
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key — 1184 bytes.
    pub mlkem: [u8; MLKEM_EK_LEN],
}

impl HybridRecipient {
    pub fn new(x25519: [u8; 32], mlkem: [u8; MLKEM_EK_LEN]) -> Self {
        Self { x25519, mlkem }
    }
}

/// Cipher algorithm identifiers stored in the Arsenic header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherId {
    DeoxysII256 = 0x02,
    XChaCha20Poly1305 = 0x03,
    Aes256GcmSiv = 0x04,
}

impl CipherId {
    pub fn from_byte(b: u8) -> Result<Self, crate::errors::CoreErr> {
        match b {
            0x02 => Ok(Self::DeoxysII256),
            0x03 => Ok(Self::XChaCha20Poly1305),
            0x04 => Ok(Self::Aes256GcmSiv),
            _ => Err(crate::errors::CoreErr::DecryptFail(format!(
                "Unknown cipher ID: {b:#x}"
            ))),
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ArsenicStrength {
    Interactive,
    Sensitive,
}

#[derive(Clone)]
pub struct ArsenicParams {
    pub t_cost: u32,
    pub m_cost: u32,
    pub p_cost: u32,
    pub hdr_cipher: CipherId,
    pub pld_cipher: CipherId,
    pub metadata: EnvelopeMetadata,
    /// Hybrid (X25519 + ML-KEM-768) recipients. Each gets an independent keyslot.
    pub recipients: Vec<HybridRecipient>,
}

impl Default for ArsenicParams {
    fn default() -> Self {
        ArsenicStrength::Interactive.into()
    }
}

impl From<ArsenicStrength> for ArsenicParams {
    fn from(s: ArsenicStrength) -> Self {
        match s {
            ArsenicStrength::Interactive => Self {
                t_cost: 4,
                m_cost: 256 * 1024,
                p_cost: 4,
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                recipients: vec![],
            },
            ArsenicStrength::Sensitive => Self {
                t_cost: 12,
                m_cost: 1024 * 1024,
                p_cost: 4,
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                recipients: vec![],
            },
        }
    }
}
