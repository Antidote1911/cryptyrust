mod crypto;
pub(crate) mod header;
mod serpent_gcm;

pub use crypto::{decrypt_arsenic, encrypt_arsenic, rekey_arsenic};

// Safety limits (DoS protection)
pub const MAX_ARGON2_RAM_KB: u32 = 8 * 1024 * 1024; // 8 GB
pub const MAX_HEADER_TOTAL_SIZE: u16 = 4096;

// Block size constants
pub const BLOCK_SIZE_4MB: usize = 4 * 1024 * 1024;
pub const BLOCK_SIZE_32MB: usize = 32 * 1024 * 1024;
pub const LARGE_FILE_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

pub const BLOCK_ID_4MB: u8 = 0x01;
pub const BLOCK_ID_32MB: u8 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ArsenicStrength {
    Interactive,
    Sensitive,
}

pub struct ArsenicParams {
    pub t_cost: u32,
    pub m_cost: u32,
    pub p_cost: u32,
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
            },
            ArsenicStrength::Sensitive => Self {
                t_cost: 12,
                m_cost: 1024 * 1024, // 1 GB
                p_cost: 4,
            },
        }
    }
}
