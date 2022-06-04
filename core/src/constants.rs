#![allow(dead_code)]
use crate::header::HeaderVersion;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

//// Crypto constants
pub const MSGLEN: usize = 10*1024;
pub const MAGICNUMBER: [u8; 4] = [0x43, 0x52, 0x59, 0x50];
pub const SALTLEN: usize = 16;
pub const KEYLEN: usize = 32;
pub const TAGLEN: usize = 16;

pub const VERSION: HeaderVersion = HeaderVersion::V1;

// Argon 2 Interactive derivation
pub const ARGON2_INTERACTIVE_PARALELISM:u32 = 4;
pub const ARGON2_INTERACTIVE_MEMORY:u32 = 1024 * 10;
pub const ARGON2_INTERACTIVE_ITERATIONS:u32 = 4;

// Argon 2 Moderate derivation
pub const ARGON2_MODERATE_PARALELISM:u32 = 4;
pub const ARGON2_MODERATE_MEMORY:u32 = 1024 * 100;
pub const ARGON2_MODERATE_ITERATIONS:u32 = 8;

// Argon 2 Sensitive derivation
pub const ARGON2_SENSITIVE_PARALELISM:u32 = 4;
pub const ARGON2_SENSITIVE_MEMORY:u32 = 1024 * 1000;
pub const ARGON2_SENSITIVE_ITERATIONS:u32 = 12;