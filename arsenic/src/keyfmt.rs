//! Arsenic key encoding — bech32 without checksum, same convention as age.
//!
//! Public key  : `arsenic1{bech32}`           — 60 chars — safe to share
//! Private key : `ARSENIC-SECRET-KEY-1{BECH32}` — 72 chars — uppercase signals danger
//!
//! Alphabet: `qpzry9x8gf2tvdw0s3jn54khce6mua7l`  (32 chars, 5 bits each)
//! 32 bytes = 256 bits → ⌈256/5⌉ = 52 bech32 characters.

/// bech32 alphabet.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Human-readable part for X25519 public keys.
pub const PUBKEY_HRP: &str = "arsenic1";
/// Human-readable part for private keys (uppercase intentional — signals secrecy).
pub const PRIVKEY_HRP: &str = "ARSENIC-SECRET-KEY-1";
/// Human-readable part for ML-KEM-768 public (encapsulation) keys.
pub const MLKEM_PUBKEY_HRP: &str = "arsenic1m";

const fn build_rev() -> [u8; 128] {
    let mut t = [0xffu8; 128];
    let mut i = 0usize;
    while i < 32 {
        t[CHARSET[i] as usize] = i as u8;
        i += 1;
    }
    t
}
const REV: [u8; 128] = build_rev();

pub fn bech32_encode_upper(data: &[u8]) -> String { bech32_encode(data).to_uppercase() }
pub fn bech32_decode_lower(s: &str) -> Option<Vec<u8>> { bech32_decode(s) }

fn bech32_encode(data: &[u8]) -> String {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity((data.len() * 8 + 4) / 5);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CHARSET[((acc >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(CHARSET[((acc << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).expect("bech32 chars are valid UTF-8")
}

fn bech32_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for b in s.bytes() {
        if b >= 128 {
            return None;
        }
        let val = REV[b as usize];
        if val == 0xff {
            return None;
        }
        acc = (acc << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Remaining bits must be zero padding.
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Encode a 32-byte X25519 public key → `arsenic1{bech32}` (60 chars).
pub fn encode_pubkey(bytes: &[u8; 32]) -> String {
    format!("{}{}", PUBKEY_HRP, bech32_encode(bytes))
}

/// Decode an `arsenic1…` string → 32 bytes, or `None` if malformed.
pub fn decode_pubkey(s: &str) -> Option<[u8; 32]> {
    let data = s.to_lowercase();
    let inner = data.strip_prefix(PUBKEY_HRP)?;
    bech32_decode(inner)?.try_into().ok()
}

/// Encode a 32-byte X25519 private key → `ARSENIC-SECRET-KEY-1{BECH32}` (72 chars).
pub fn encode_privkey(bytes: &[u8; 32]) -> String {
    format!("{}{}", PRIVKEY_HRP, bech32_encode(bytes).to_uppercase())
}

/// Decode an `ARSENIC-SECRET-KEY-1…` string → 32 bytes, or `None` if malformed.
pub fn decode_privkey(s: &str) -> Option<[u8; 32]> {
    let upper = s.to_uppercase();
    let inner = upper.strip_prefix(PRIVKEY_HRP)?;
    bech32_decode(&inner.to_lowercase())?.try_into().ok()
}

/// Human-readable part for the 64-byte ML-KEM seed (uppercase signals secrecy).
pub const MLKEM_SEED_HRP: &str = "ARSENIC-MLKEM-SEED-1";

/// Human-readable part for the 1952-byte ML-DSA-65 verifying (public) key.
pub const MLDSA_VK_HRP: &str = "ARSENIC-SIGN-PUB-1";

/// Encode a 1952-byte ML-DSA-65 verifying key → `ARSENIC-SIGN-PUB-1{BECH32}`.
pub fn encode_mldsa_vk(bytes: &[u8; 1952]) -> String {
    format!("{}{}", MLDSA_VK_HRP, bech32_encode(bytes).to_uppercase())
}

/// Decode an `ARSENIC-SIGN-PUB-1…` string → 1952 bytes, or `None` if malformed.
pub fn decode_mldsa_vk(s: &str) -> Option<[u8; 1952]> {
    let upper = s.to_uppercase();
    let inner = upper.strip_prefix(MLDSA_VK_HRP)?;
    bech32_decode(&inner.to_lowercase())?.try_into().ok()
}

/// Encode a 64-byte ML-KEM seed → `ARSENIC-MLKEM-SEED-1{BECH32}` (~123 chars).
pub fn encode_mlkem_seed(bytes: &[u8; 64]) -> String {
    format!("{}{}", MLKEM_SEED_HRP, bech32_encode(bytes).to_uppercase())
}

/// Decode an `ARSENIC-MLKEM-SEED-1…` string → 64 bytes, or `None` if malformed.
pub fn decode_mlkem_seed(s: &str) -> Option<[u8; 64]> {
    let upper = s.to_uppercase();
    let inner = upper.strip_prefix(MLKEM_SEED_HRP)?;
    bech32_decode(&inner.to_lowercase())?.try_into().ok()
}

/// Encode a 1184-byte ML-KEM-768 encapsulation key → `arsenic1m{bech32}`.
pub fn encode_mlkem_pubkey(bytes: &[u8; 1184]) -> String {
    format!("{}{}", MLKEM_PUBKEY_HRP, bech32_encode(bytes))
}

/// Decode an `arsenic1m…` string → 1184 bytes, or `None` if malformed.
pub fn decode_mlkem_pubkey(s: &str) -> Option<[u8; 1184]> {
    let lower = s.to_lowercase();
    let inner = lower.strip_prefix(MLKEM_PUBKEY_HRP)?;
    bech32_decode(inner)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_round_trip() {
        let k: [u8; 32] = core::array::from_fn(|i| i as u8);
        let enc = encode_pubkey(&k);
        assert!(enc.starts_with("arsenic1"));
        assert_eq!(enc.len(), 60);
        assert_eq!(decode_pubkey(&enc).unwrap(), k);
    }

    #[test]
    fn privkey_round_trip() {
        let k: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);
        let enc = encode_privkey(&k);
        assert!(enc.starts_with("ARSENIC-SECRET-KEY-1"));
        assert_eq!(enc.len(), 72);
        assert_eq!(decode_privkey(&enc).unwrap(), k);
    }

    #[test]
    fn decode_case_insensitive() {
        let k = [0xabu8; 32];
        let enc = encode_pubkey(&k);
        assert_eq!(decode_pubkey(&enc.to_uppercase().replacen("ARSENIC1", "arsenic1", 1)).unwrap(), k);
    }

    #[test]
    fn invalid_prefix_returns_none() {
        assert!(decode_pubkey("age1qpzry9x8gf2tvdw0s3jn54khce6mua7l").is_none());
        assert!(decode_privkey("AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KH").is_none());
    }
}
