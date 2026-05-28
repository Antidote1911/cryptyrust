pub mod bench;
mod cipher_dispatch;
mod crypto;
pub(crate) mod header;

pub use crypto::{decrypt_arsenic, encrypt_arsenic, rekey_arsenic};
pub use header::{EnvelopeMetadata, MIN_HEADER_TOTAL_SIZE, WRAPPED_DEK_LEN};

// Safety limits (DoS protection)
pub const MAX_ARGON2_RAM_KB: u32 = 8 * 1024 * 1024; // 8 GB
pub const MAX_HEADER_TOTAL_SIZE: u16 = 4096;

// Block size constants
pub const BLOCK_SIZE_4MB: usize = 4 * 1024 * 1024;
pub const BLOCK_SIZE_32MB: usize = 32 * 1024 * 1024;
pub const LARGE_FILE_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

pub const BLOCK_ID_4MB: u8 = 0x01;
pub const BLOCK_ID_32MB: u8 = 0x02;

/// Default zstd compression level (zstd's own default: good ratio, fast).
pub const ZSTD_DEFAULT_LEVEL: i32 = 3;

/// Cipher algorithm identifiers stored in the Arsenic V1 header.
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

/// Compression algorithm applied to the plaintext before block splitting.
/// Stored as a single byte in the public header (covered by HeaderMAC).
///
/// `None` is the default — existing files without compression are unaffected.
/// `Zstd(level)` compresses the entire plaintext with zstd before encryption;
/// the level (1–22) is an encryption-time parameter and is NOT stored in the file
/// (decompression does not need it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Compression {
    #[default]
    None,
    Zstd(i32),
}

impl Compression {
    /// Map to the header byte stored at `0x09`.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::None => header::COMPRESS_NONE,
            Self::Zstd(_) => header::COMPRESS_ZSTD,
        }
    }

    /// Reconstruct from the header byte for decryption.
    /// The level is irrelevant for decompression, so `Zstd(0)` is returned.
    pub fn from_byte(b: u8) -> Result<Self, crate::errors::CoreErr> {
        match b {
            header::COMPRESS_NONE => Ok(Self::None),
            header::COMPRESS_ZSTD => Ok(Self::Zstd(0)), // level unused on decrypt
            _ => Err(crate::errors::CoreErr::DecryptFail(format!(
                "Unknown compression ID: {b:#x}"
            ))),
        }
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
    /// Optional metadata stored inside the encrypted TLV envelope.
    pub metadata: EnvelopeMetadata,
    /// Compression applied before block encryption. Disabled by default.
    pub compression: Compression,
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
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                compression: Compression::None,
            },
            ArsenicStrength::Sensitive => Self {
                t_cost: 12,
                m_cost: 1024 * 1024, // 1 GB
                p_cost: 4,
                hdr_cipher: CipherId::DeoxysII256,
                pld_cipher: CipherId::XChaCha20Poly1305,
                metadata: EnvelopeMetadata::default(),
                compression: Compression::None,
            },
        }
    }
}
