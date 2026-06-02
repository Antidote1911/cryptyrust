pub mod bench;
pub mod armor;
mod cipher_dispatch;
mod crypto;
pub(crate) mod header;
pub(crate) mod hybrid_kem;

pub use crypto::{
    decrypt_arsenic, decrypt_arsenic_with_key, encrypt_arsenic, find_decrypting_key,
    find_slot_for_privkey, list_recipients, rekey_arsenic,
    build_header_with_added_recipient, build_header_with_removed_recipient,
    build_header_with_added_passphrase, build_header_with_removed_passphrase,
    encrypt_arsenic_to_writer,
    decrypt_block_at, decrypt_block_at_with_key,
    try_extra_passphrase_slots,
    HybridPrivKey,
};
pub use armor::{armor, dearmor};

use crate::arsenic::hybrid_kem::EK_LEN as MLKEM_EK_LEN;
pub use header::{
    HybridKeyslot, HybridKeyslot1024, ExtraPassSlot,
    EnvelopeMetadata, MIN_HEADER_TOTAL_SIZE, WRAPPED_DEK_LEN,
    EXTRA_PASS_COUNT_LEN, EXTRA_PASS_SLOT_LEN, MAX_EXTRA_PASSPHRASE_SLOTS,
    COMPRESS_ZSTD,
};
pub use header::{MAX_T_COST, MAX_P_COST};

// Safety limits (DoS protection before running any KDF).
// u32 header_total_size allows headers up to 64 MiB, supporting ~700 000 recipients.
pub const MAX_ARGON2_RAM_KB: u32 = 4 * 1024 * 1024; // 4 GiB
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
    /// ML-KEM-768 encapsulation key — 1184 bytes (always present).
    pub mlkem: [u8; MLKEM_EK_LEN],
    /// ML-KEM-1024 encapsulation key — 1568 bytes (present when KemLevel::L1024).
    pub mlkem_1024: Option<[u8; 1568]>,
}

impl HybridRecipient {
    pub fn new(x25519: [u8; 32], mlkem: [u8; MLKEM_EK_LEN]) -> Self {
        Self { x25519, mlkem, mlkem_1024: None }
    }

    pub fn new_with_1024(x25519: [u8; 32], mlkem: [u8; MLKEM_EK_LEN], mlkem_1024: [u8; 1568]) -> Self {
        Self { x25519, mlkem, mlkem_1024: Some(mlkem_1024) }
    }
}

/// ML-KEM security level for asymmetric keyslots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KemLevel {
    /// ML-KEM-768 — NIST Level 3 (~180-bit quantum security). Default.
    #[default]
    L768,
    /// ML-KEM-1024 — NIST Level 5 (~256-bit quantum security).
    L1024,
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
    /// Hybrid recipients — each gets an independent keyslot.
    pub recipients: Vec<HybridRecipient>,
    /// ML-KEM security level for new keyslots (default: L768).
    pub kem_level: KemLevel,
    /// Sender's display name — embedded in the public header so the recipient
    /// can add the sender as a contact and encrypt back without a .pubkey exchange.
    pub sender_name: Option<String>,
    /// Sender's X25519 public key (32 bytes).
    pub sender_x25519_pk: Option<[u8; 32]>,
    /// Sender's ML-KEM-768 encapsulation key (1184 bytes).
    pub sender_mlkem_pk: Option<[u8; 1184]>,
    /// zstd compression level (1–22).  `None` = disabled.
    ///
    /// # Security warning
    /// Enabling compression leaks plaintext entropy via ciphertext size.
    /// See `COMPRESSION_LEAKS_SIZE` for details.
    pub compress: Option<i32>,
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
                t_cost: 4, m_cost: 256 * 1024, p_cost: 4,
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                recipients: vec![],
                kem_level: KemLevel::L768,
                sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
                compress: None,
            },
            ArsenicStrength::Sensitive => Self {
                t_cost: 12, m_cost: 1024 * 1024, p_cost: 4,
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                recipients: vec![],
                kem_level: KemLevel::L768,
                sender_name: None, sender_x25519_pk: None, sender_mlkem_pk: None,
                compress: None,
            },
        }
    }
}
