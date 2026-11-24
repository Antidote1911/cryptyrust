// Base64 bit packing: the casts keep the low bits on purpose, and the output
// alphabet is ASCII so the UTF-8 conversions cannot fail.
#![allow(clippy::cast_possible_truncation, clippy::expect_used, clippy::missing_panics_doc)]

//! ASCII armor — base64 encoding with PEM-style header/footer.
//!
//! Armor makes a binary `.arsn` file safe to transmit over text channels
//! (email body, JSON values, configuration files, copy-paste).
//!
//! # Warning
//! Armor reveals the exact ciphertext length, which leaks a lower bound on
//! the plaintext size.  For size-sensitive data, transport the raw `.arsn`
//! binary instead.

use crate::errors::CoreErr;

const ARMOR_BEGIN: &str = "-----BEGIN ARSENIC ENCRYPTED FILE-----";
const ARMOR_END: &str   = "-----END ARSENIC ENCRYPTED FILE-----";
const LINE_WIDTH: usize = 64;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let cap = data.len().div_ceil(3) * 4;
    let mut out = Vec::with_capacity(cap);
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        out.push(B64[((n >> 18) & 63) as usize]);
        out.push(B64[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() >= 2 { B64[((n >> 6) & 63) as usize] } else { b'=' });
        out.push(if chunk.len() >= 3 { B64[(n & 63) as usize]         } else { b'=' });
    }
    String::from_utf8(out).expect("base64 alphabet is ASCII")
}

fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) { return None; }
    let mut rev = [0xffu8; 256];
    for (i, &c) in B64.iter().enumerate() { rev[c as usize] = i as u8; }

    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                vals[i] = 0;
            } else {
                let v = rev[c as usize];
                if v == 0xff { return None; }
                vals[i] = u32::from(v);
            }
        }
        if pad > 2 { return None; }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Some(out)
}

/// Encode an Arsenic ciphertext as ASCII armor.
///
/// The output is a UTF-8 string with a `BEGIN` header, base64 body (64-char
/// lines), and an `END` footer.  It can be embedded in email, config files,
/// or any text channel.
///
/// # Warning
/// The armor length reveals a lower bound on the plaintext size.
/// See `ARMOR_LEAKS_SIZE` for details.
pub fn armor(data: &[u8]) -> String {
    let b64 = b64_encode(data);
    let mut out = String::with_capacity(b64.len() + 200);
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    for line in b64.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out
}

/// Decode ASCII armor back to the raw binary ciphertext.
///
/// Returns `Err(DecryptFail)` if the `BEGIN` header, `END` footer, or base64
/// content is missing or malformed.
pub fn dearmor(s: &str) -> Result<Vec<u8>, CoreErr> {
    let begin = s.find(ARMOR_BEGIN)
        .ok_or_else(|| CoreErr::DecryptFail("Missing armor header".into()))?;
    let body_start = begin + ARMOR_BEGIN.len();

    let end = s[body_start..].find(ARMOR_END)
        .map(|p| body_start + p)
        .ok_or_else(|| CoreErr::DecryptFail("Missing armor footer".into()))?;

    // Strip all whitespace from the base64 body.
    let b64: Vec<u8> = s[body_start..end]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    b64_decode(&b64)
        .ok_or_else(|| CoreErr::DecryptFail("Invalid base64 in armor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty() {
        assert_eq!(dearmor(&armor(&[])).unwrap(), b"");
    }

    #[test]
    fn round_trip_arbitrary() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(dearmor(&armor(&data)).unwrap(), data);
    }

    #[test]
    fn line_width() {
        let data = vec![0u8; 128];
        let armored = armor(&data);
        for line in armored.lines() {
            if line.starts_with('-') { continue; }
            assert!(line.len() <= LINE_WIDTH, "line too long: {}", line.len());
        }
    }

    #[test]
    fn missing_header_rejected() {
        let bad = "no header here\n-----END ARSENIC ENCRYPTED FILE-----\n";
        assert!(dearmor(bad).is_err());
    }

    #[test]
    fn missing_footer_rejected() {
        let bad = "-----BEGIN ARSENIC ENCRYPTED FILE-----\nYWJj\n";
        assert!(dearmor(bad).is_err());
    }

    #[test]
    fn invalid_base64_rejected() {
        let bad = "-----BEGIN ARSENIC ENCRYPTED FILE-----\n!!!\n-----END ARSENIC ENCRYPTED FILE-----\n";
        assert!(dearmor(bad).is_err());
    }
}
