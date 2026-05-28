mod cipher_dispatch;
mod crypto;
pub(crate) mod header;
mod serpent_gcm;

pub use crypto::{decrypt_arsenic, encrypt_arsenic, rekey_arsenic};
pub use header::TOTAL_HEADER_LEN;

// Safety limits (DoS protection)
pub const MAX_ARGON2_RAM_KB: u32 = 8 * 1024 * 1024; // 8 GB
pub const MAX_HEADER_TOTAL_SIZE: u16 = 4096;

// Block size constants
pub const BLOCK_SIZE_4MB: usize = 4 * 1024 * 1024;
pub const BLOCK_SIZE_32MB: usize = 32 * 1024 * 1024;
pub const LARGE_FILE_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

pub const BLOCK_ID_4MB: u8 = 0x01;
pub const BLOCK_ID_32MB: u8 = 0x02;

/// Cipher algorithm identifiers stored in the Arsenic V2 header.
///
/// Both the header-envelope cipher (bytes 0x07) and the payload-block cipher
/// (byte 0x08) are independently selectable from this set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherId {
    /// Serpent-256 in GCM mode — manual NIST SP 800-38D implementation.
    SerpentGcm = 0x02,
    /// XChaCha20-Poly1305 (192-bit nonce).
    XChaCha20Poly1305 = 0x03,
    /// AES-256-GCM-SIV (nonce misuse-resistant GCM).
    Aes256GcmSiv = 0x04,
}

impl CipherId {
    pub fn from_byte(b: u8) -> Result<Self, crate::errors::CoreErr> {
        match b {
            0x02 => Ok(Self::SerpentGcm),
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
    /// Cipher used to encrypt the key-envelope in the header.
    pub hdr_cipher: CipherId,
    /// Cipher used to encrypt each payload block.
    pub pld_cipher: CipherId,
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
                m_cost: 256 * 1024, // 256 MB
                p_cost: 4,
                hdr_cipher: CipherId::SerpentGcm,
                pld_cipher: CipherId::XChaCha20Poly1305,
            },
            ArsenicStrength::Sensitive => Self {
                t_cost: 12,
                m_cost: 1024 * 1024, // 1 GB
                p_cost: 4,
                hdr_cipher: CipherId::SerpentGcm,
                pld_cipher: CipherId::XChaCha20Poly1305,
            },
        }
    }
}
