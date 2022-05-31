#![allow(dead_code)]
use crate::header::HeaderVersion;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

//// Crypto constants
pub const MSGLEN: usize = 10*1024;
pub const SIGNATURE: [u8; 4] = [0x43, 0x52, 0x59, 0x50];
pub const SALTLEN: usize = 16;
pub const NONCELEN:usize = 7;
pub const XNONCELEN:usize = 19;
pub const KEYLEN: usize = 32;
pub const TAGLEN: usize = 16;

pub const VERSION: HeaderVersion = HeaderVersion::V1;

// keygen constants
pub const ARGON2PARALELISM:u32 = 4;
pub const ARGON2MEMORY:u32 = 16 * 1024;
pub const ARGON2ITERATIONS:u32 = 8;