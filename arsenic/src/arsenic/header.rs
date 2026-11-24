//! Arsenic V2 header: layout, serialization and strict parsing.
//!
//! ```text
//! Public parameters (65 bytes)
//!   0x00   4  magic "ARSN"
//!   0x04   2  version (00 02)
//!   0x06   1  KDF id (01 = Argon2id)
//!   0x07   1  header cipher id
//!   0x08   1  payload cipher id
//!   0x09   4  header_total_size (u32 LE)
//!   0x0D  16  Argon2id salt (shared by every password slot)
//!   0x1D   4  t_cost     0x21  4  m_cost (KiB)     0x25  4  p_cost
//!   0x29  24  file_base_nonce
//! Key slots
//!   u32 count, then 92-byte password slots
//!   u32 count, then 1180-byte ML-KEM-768 slots
//!   u32 count, then 1660-byte ML-KEM-1024 slots
//! Protected metadata
//!   u32 length, then nonce(12) || AEAD(meta TLV)
//! Sender
//!   present(1) [name_len(u16) name x25519(32) mlkem(1184)]
//! HeaderMAC (32 bytes)
//!   BLAKE3 keyed hash, key derived from the DEK, over every byte before it.
//! ```
//!
//! The MAC covers the whole header, so any holder of a valid key (password or
//! keypair) detects a modified slot list, metadata blob or sender identity.

// Lint exemptions for this module — none of them hides a reachable failure:
//  * unwrap/expect: slice → fixed-size array conversions whose lengths are
//    constants or were checked by the cursor just above.
//  * casts: sizes bounded by the format limits checked at build time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_possible_truncation)]

use crate::errors::CoreErr;

pub const MAGIC: [u8; 4] = [0x41, 0x52, 0x53, 0x4E]; // "ARSN"
pub const VERSION: [u8; 2] = [0x00, 0x02];
pub const KDF_ID_ARGON2ID: u8 = 0x01;

/// Hard upper bounds on Argon2id parameters, enforced when encrypting and
/// before any KDF run when decrypting.
pub const MAX_T_COST: u32 = 64;
pub const MAX_P_COST: u32 = 16;

/// Fixed-size public parameters at the start of every file.
pub const PUB_HEADER_LEN: usize = 65;
/// Offset of the u32 `header_total_size` field.
pub const HEADER_SIZE_OFFSET: usize = 9;
/// Every supported AEAD produces a 16-byte tag.
pub const AEAD_TAG: usize = 16;
pub const HEADER_MAC_LEN: usize = 32;
pub const COUNT_LEN: usize = 4;

/// AEAD(wrapping key, DEK) = 32 ciphertext + 16 tag.
pub const WRAPPED_DEK_LEN: usize = 32 + AEAD_TAG;

// ── Password slots ────────────────────────────────────────────────────────────

/// nonce(12) + wrapped DEK(48) + check tag(32).
pub const PASSWORD_SLOT_LEN: usize = 12 + WRAPPED_DEK_LEN + 32;
pub const MAX_PASSWORD_SLOTS: usize = 16;

// ── Hybrid keyslots ───────────────────────────────────────────────────────────

pub const ASYM_KEYSLOT_MLKEM_CT_LEN: usize = 1088;
/// ML-KEM-768 keyslot = 32 + 1088 + 12 + 48 = 1180 bytes.
pub const ASYM_KEYSLOT_LEN: usize = 32 + ASYM_KEYSLOT_MLKEM_CT_LEN + 12 + WRAPPED_DEK_LEN;
pub const ASYM_1024_KEYSLOT_MLKEM_CT_LEN: usize = 1568;
/// ML-KEM-1024 keyslot = 32 + 1568 + 12 + 48 = 1660 bytes.
pub const ASYM_1024_KEYSLOT_LEN: usize = 32 + ASYM_1024_KEYSLOT_MLKEM_CT_LEN + 12 + WRAPPED_DEK_LEN;
/// Limit on hybrid keyslots, 768 and 1024 counted together.
pub const MAX_ASYM_KEYSLOTS: usize = 256;

// ── Metadata ──────────────────────────────────────────────────────────────────

pub const COMPRESS_ZSTD: u8 = 0x01;
pub const META_NONCE_LEN: usize = 12;
/// Longest filename / comment / sender name, in bytes.
pub const MAX_TEXT_LEN: usize = 255;
/// Mandatory TLV entries: `OriginalSize` (2+8) and `BlockSizeId` (2+1).
pub const META_TLV_MANDATORY_PT_LEN: usize = (2 + 8) + (2 + 1);
/// Upper bound on the encrypted metadata blob.
pub const MAX_PROTECTED_META_LEN: usize = 4096;

/// Smallest possible header: no key slot, mandatory metadata, no sender.
pub const MIN_HEADER_TOTAL_SIZE: usize = PUB_HEADER_LEN
    + 3 * COUNT_LEN
    + COUNT_LEN + META_NONCE_LEN + META_TLV_MANDATORY_PT_LEN + AEAD_TAG
    + 1
    + HEADER_MAC_LEN;

pub mod tlv_tags {
    pub const ORIGINAL_SIZE: u8 = 0x03;
    pub const BLOCK_SIZE_ID: u8 = 0x05;
    /// Compression algorithm (0x01 = zstd). Absent = no compression.
    pub const COMPRESS_ALGO_ID: u8 = 0x07;
    pub const FILENAME: u8 = 0x10;
    pub const COMMENT: u8 = 0x11;
    pub const TIMESTAMP_SECS: u8 = 0x12;
    /// Unknown tags at or above this value may be ignored by a reader; unknown
    /// tags below it change how the file must be read and are an error.
    pub const FIRST_IGNORABLE: u8 = 0x80;
}

pub const SENDER_PRESENT_NONE: u8 = 0x00;
pub const SENDER_PRESENT: u8 = 0x01;
const SENDER_KEYS_LEN: usize = 32 + 1184;

// ── Structs ───────────────────────────────────────────────────────────────────

#[derive(Default, Debug, Clone)]
pub struct EnvelopeMetadata {
    pub filename: Option<String>,
    pub comment: Option<String>,
    pub timestamp_secs: Option<u64>,
}

/// Sender identity stored in clear in the header.
///
/// It can be read without any key, but only a successful decryption proves it
/// was not altered after the file was written (the `HeaderMAC` covers it). It
/// stays a *claim*: whoever encrypted the file chose it.
#[derive(Clone, Debug)]
pub struct SenderInfo {
    pub name: String,
    pub x25519_pk: [u8; 32],
    pub mlkem_pk: [u8; 1184],
}

/// One password slot — 92 bytes.
///
/// `check` is a keyed hash under a key derived from the Argon2id output. It
/// tells, without any AEAD attempt, whether a password belongs to this slot,
/// and it commits the slot to a single key.
#[derive(Clone)]
pub struct PasswordSlot {
    pub nonce: [u8; 12],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub check: [u8; 32],
}

/// One hybrid (X25519 + ML-KEM-768) keyslot — 1180 bytes.
#[derive(Clone)]
pub struct HybridKeyslot {
    pub ephemeral_x25519: [u8; 32],
    pub mlkem_ct: [u8; ASYM_KEYSLOT_MLKEM_CT_LEN],
    pub kek_nonce: [u8; 12],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

/// One hybrid (X25519 + ML-KEM-1024) keyslot — 1660 bytes.
#[derive(Clone)]
pub struct HybridKeyslot1024 {
    pub ephemeral_x25519: [u8; 32],
    pub mlkem_ct: [u8; ASYM_1024_KEYSLOT_MLKEM_CT_LEN],
    pub kek_nonce: [u8; 12],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

#[derive(Clone)]
pub struct PublicHeader {
    pub header_total_size: u32,
    pub salt: [u8; 16],
    pub t_cost: u32,
    pub m_cost: u32,
    pub p_cost: u32,
    pub file_base_nonce: [u8; 24],
    pub hdr_cipher_id: u8,
    pub pld_cipher_id: u8,
}

/// Plaintext of the protected metadata.
#[derive(Clone, Debug, Default)]
pub struct EnvelopeContent {
    /// Size of the original (uncompressed) plaintext.
    pub original_size: u64,
    pub block_size_id: u8,
    /// `None` = no compression.
    pub compress_algo: Option<u8>,
    pub filename: Option<String>,
    pub comment: Option<String>,
    pub timestamp_secs: Option<u64>,
}

impl EnvelopeContent {
    pub fn metadata(&self) -> EnvelopeMetadata {
        EnvelopeMetadata {
            filename: self.filename.clone(),
            comment: self.comment.clone(),
            timestamp_secs: self.timestamp_secs,
        }
    }
}

/// A complete header.
#[derive(Clone)]
pub struct Header {
    pub public: PublicHeader,
    pub password_slots: Vec<PasswordSlot>,
    pub hybrid_keyslots: Vec<HybridKeyslot>,
    pub hybrid_keyslots_1024: Vec<HybridKeyslot1024>,
    /// nonce(12) || AEAD ciphertext of the metadata TLV.
    pub protected_meta: Vec<u8>,
    pub sender: Option<SenderInfo>,
    pub mac: [u8; HEADER_MAC_LEN],
}

// ── Small helpers ─────────────────────────────────────────────────────────────

/// `s` cut to at most [`MAX_TEXT_LEN`] bytes without splitting a character.
pub fn truncate_text(s: &str) -> &str {
    if s.len() <= MAX_TEXT_LEN {
        return s;
    }
    let mut end = MAX_TEXT_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn bad(msg: &str) -> CoreErr {
    CoreErr::DecryptFail(format!("Malformed header: {msg}"))
}

/// Forward-only reader that never panics on short input.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreErr> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        let end = end.ok_or_else(|| bad("truncated"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CoreErr> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    fn u8(&mut self) -> Result<u8, CoreErr> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoreErr> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CoreErr> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

// ── Slot (de)serialization ────────────────────────────────────────────────────

impl PasswordSlot {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.check);
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, CoreErr> {
        Ok(Self { nonce: c.array()?, wrapped_dek: c.array()?, check: c.array()? })
    }
}

impl HybridKeyslot {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ephemeral_x25519);
        out.extend_from_slice(&self.mlkem_ct);
        out.extend_from_slice(&self.kek_nonce);
        out.extend_from_slice(&self.wrapped_dek);
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, CoreErr> {
        Ok(Self {
            ephemeral_x25519: c.array()?,
            mlkem_ct: c.array()?,
            kek_nonce: c.array()?,
            wrapped_dek: c.array()?,
        })
    }
}

impl HybridKeyslot1024 {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ephemeral_x25519);
        out.extend_from_slice(&self.mlkem_ct);
        out.extend_from_slice(&self.kek_nonce);
        out.extend_from_slice(&self.wrapped_dek);
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, CoreErr> {
        Ok(Self {
            ephemeral_x25519: c.array()?,
            mlkem_ct: c.array()?,
            kek_nonce: c.array()?,
            wrapped_dek: c.array()?,
        })
    }
}

// ── Header (de)serialization ──────────────────────────────────────────────────

impl Header {
    /// Total size of the serialized header, MAC included.
    pub fn total_size(&self) -> usize {
        let sender = self.sender.as_ref().map_or(0, |s| {
            2 + truncate_text(&s.name).len() + SENDER_KEYS_LEN
        });
        PUB_HEADER_LEN
            + COUNT_LEN + self.password_slots.len() * PASSWORD_SLOT_LEN
            + COUNT_LEN + self.hybrid_keyslots.len() * ASYM_KEYSLOT_LEN
            + COUNT_LEN + self.hybrid_keyslots_1024.len() * ASYM_1024_KEYSLOT_LEN
            + COUNT_LEN + self.protected_meta.len()
            + 1 + sender
            + HEADER_MAC_LEN
    }

    /// Number of key slots of any kind.
    pub const fn key_slot_count(&self) -> usize {
        self.password_slots.len() + self.hybrid_keyslots.len() + self.hybrid_keyslots_1024.len()
    }

    /// Every byte covered by the `HeaderMAC`, i.e. the header without its last
    /// 32 bytes. `header_total_size` is recomputed from the content.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let total = self.total_size();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION);
        out.push(KDF_ID_ARGON2ID);
        out.push(self.public.hdr_cipher_id);
        out.push(self.public.pld_cipher_id);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&self.public.salt);
        out.extend_from_slice(&self.public.t_cost.to_le_bytes());
        out.extend_from_slice(&self.public.m_cost.to_le_bytes());
        out.extend_from_slice(&self.public.p_cost.to_le_bytes());
        out.extend_from_slice(&self.public.file_base_nonce);
        debug_assert_eq!(out.len(), PUB_HEADER_LEN);

        out.extend_from_slice(&(self.password_slots.len() as u32).to_le_bytes());
        for s in &self.password_slots {
            s.write(&mut out);
        }
        out.extend_from_slice(&(self.hybrid_keyslots.len() as u32).to_le_bytes());
        for s in &self.hybrid_keyslots {
            s.write(&mut out);
        }
        out.extend_from_slice(&(self.hybrid_keyslots_1024.len() as u32).to_le_bytes());
        for s in &self.hybrid_keyslots_1024 {
            s.write(&mut out);
        }
        out.extend_from_slice(&(self.protected_meta.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.protected_meta);
        match &self.sender {
            Some(s) => {
                let name = truncate_text(&s.name).as_bytes();
                out.push(SENDER_PRESENT);
                out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                out.extend_from_slice(name);
                out.extend_from_slice(&s.x25519_pk);
                out.extend_from_slice(&s.mlkem_pk);
            }
            None => out.push(SENDER_PRESENT_NONE),
        }
        debug_assert_eq!(out.len() + HEADER_MAC_LEN, total);
        out
    }

    /// Full serialized header: signed bytes followed by `self.mac`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parse a complete header. `bytes` must be exactly `header_total_size`
    /// long; any slack, short field or out-of-range count is an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoreErr> {
        if bytes.len() < PUB_HEADER_LEN || bytes[0..4] != MAGIC {
            return Err(CoreErr::BadSignature);
        }
        if bytes[4..6] != VERSION {
            return Err(CoreErr::BadHeaderVersion);
        }
        if bytes.len() < MIN_HEADER_TOTAL_SIZE {
            return Err(bad("too short"));
        }
        let mut c = Cursor { buf: bytes, pos: 6 };
        let kdf_id = c.u8()?;
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(CoreErr::DecryptFail(format!("Unknown KDF ID: {kdf_id:#x}")));
        }
        let hdr_cipher_id = c.u8()?;
        let pld_cipher_id = c.u8()?;
        let header_total_size = c.u32()?;
        if header_total_size as usize != bytes.len() {
            return Err(bad("size field does not match"));
        }
        let public = PublicHeader {
            header_total_size,
            salt: c.array()?,
            t_cost: c.u32()?,
            m_cost: c.u32()?,
            p_cost: c.u32()?,
            file_base_nonce: c.array()?,
            hdr_cipher_id,
            pld_cipher_id,
        };

        let n_pw = c.u32()? as usize;
        if n_pw > MAX_PASSWORD_SLOTS {
            return Err(bad("too many password slots"));
        }
        let password_slots =
            (0..n_pw).map(|_| PasswordSlot::read(&mut c)).collect::<Result<Vec<_>, _>>()?;

        let n_768 = c.u32()? as usize;
        if n_768 > MAX_ASYM_KEYSLOTS {
            return Err(bad("too many keyslots"));
        }
        let hybrid_keyslots =
            (0..n_768).map(|_| HybridKeyslot::read(&mut c)).collect::<Result<Vec<_>, _>>()?;

        let n_1024 = c.u32()? as usize;
        if n_768 + n_1024 > MAX_ASYM_KEYSLOTS {
            return Err(bad("too many keyslots"));
        }
        let hybrid_keyslots_1024 =
            (0..n_1024).map(|_| HybridKeyslot1024::read(&mut c)).collect::<Result<Vec<_>, _>>()?;

        let meta_len = c.u32()? as usize;
        if !(META_NONCE_LEN + AEAD_TAG..=MAX_PROTECTED_META_LEN).contains(&meta_len) {
            return Err(bad("metadata length out of range"));
        }
        let protected_meta = c.take(meta_len)?.to_vec();

        let sender = match c.u8()? {
            SENDER_PRESENT_NONE => None,
            SENDER_PRESENT => {
                let name_len = c.u16()? as usize;
                if name_len > MAX_TEXT_LEN {
                    return Err(bad("sender name too long"));
                }
                let name = String::from_utf8_lossy(c.take(name_len)?).into_owned();
                Some(SenderInfo { name, x25519_pk: c.array()?, mlkem_pk: c.array()? })
            }
            _ => return Err(bad("invalid sender marker")),
        };

        if c.remaining() != HEADER_MAC_LEN {
            return Err(bad("unexpected trailing bytes"));
        }
        let mac = c.array()?;

        Ok(Self { public, password_slots, hybrid_keyslots, hybrid_keyslots_1024, protected_meta, sender, mac })
    }
}

// ── Metadata TLV ──────────────────────────────────────────────────────────────

fn tlv_push(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    debug_assert!(value.len() <= MAX_TEXT_LEN);
    buf.push(tag);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Serialize the metadata. Text fields longer than [`MAX_TEXT_LEN`] bytes are
/// cut on a character boundary; the length never depends on `original_size`,
/// so the header size is known before the payload is written.
pub fn serialize_meta_tlv(env: &EnvelopeContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_TLV_MANDATORY_PT_LEN + 32);
    tlv_push(&mut buf, tlv_tags::ORIGINAL_SIZE, &env.original_size.to_le_bytes());
    tlv_push(&mut buf, tlv_tags::BLOCK_SIZE_ID, &[env.block_size_id]);
    if let Some(algo) = env.compress_algo {
        tlv_push(&mut buf, tlv_tags::COMPRESS_ALGO_ID, &[algo]);
    }
    for (tag, text) in [(tlv_tags::FILENAME, &env.filename), (tlv_tags::COMMENT, &env.comment)] {
        if let Some(s) = text.as_deref().map(truncate_text).filter(|s| !s.is_empty()) {
            tlv_push(&mut buf, tag, s.as_bytes());
        }
    }
    if let Some(ts) = env.timestamp_secs {
        tlv_push(&mut buf, tlv_tags::TIMESTAMP_SECS, &ts.to_le_bytes());
    }
    buf
}

pub fn deserialize_meta_tlv(buf: &[u8]) -> Result<EnvelopeContent, CoreErr> {
    fn meta_err(msg: &str) -> CoreErr {
        CoreErr::DecryptFail(format!("Malformed metadata: {msg}"))
    }
    fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), CoreErr> {
        if slot.replace(value).is_some() {
            return Err(meta_err("duplicate field"));
        }
        Ok(())
    }
    fn text(val: &[u8]) -> Result<String, CoreErr> {
        std::str::from_utf8(val).map(str::to_owned).map_err(|_| meta_err("invalid UTF-8"))
    }

    let mut original_size = None;
    let mut block_size_id = None;
    let mut compress_algo = None;
    let mut filename = None;
    let mut comment = None;
    let mut timestamp_secs = None;

    let mut c = Cursor { buf, pos: 0 };
    while c.remaining() > 0 {
        let tag = c.u8().map_err(|_| meta_err("truncated"))?;
        let len = c.u8().map_err(|_| meta_err("truncated"))? as usize;
        let val = c.take(len).map_err(|_| meta_err("truncated"))?;
        match (tag, len) {
            (tlv_tags::ORIGINAL_SIZE, 8) => {
                set(&mut original_size, u64::from_le_bytes(val.try_into().unwrap()))?;
            }
            (tlv_tags::BLOCK_SIZE_ID, 1) => set(&mut block_size_id, val[0])?,
            (tlv_tags::COMPRESS_ALGO_ID, 1) => {
                if val[0] != COMPRESS_ZSTD {
                    return Err(meta_err("unknown compression algorithm"));
                }
                set(&mut compress_algo, val[0])?;
            }
            (tlv_tags::FILENAME, _) => set(&mut filename, text(val)?)?,
            (tlv_tags::COMMENT, _) => set(&mut comment, text(val)?)?,
            (tlv_tags::TIMESTAMP_SECS, 8) => {
                set(&mut timestamp_secs, u64::from_le_bytes(val.try_into().unwrap()))?;
            }
            (t, _) if t >= tlv_tags::FIRST_IGNORABLE => {}
            _ => return Err(meta_err("unknown or malformed field")),
        }
    }

    Ok(EnvelopeContent {
        original_size: original_size.ok_or_else(|| meta_err("missing OriginalSize"))?,
        block_size_id: block_size_id.ok_or_else(|| meta_err("missing BlockSizeId"))?,
        compress_algo,
        filename,
        comment,
        timestamp_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            public: PublicHeader {
                header_total_size: 0,
                salt: [1; 16],
                t_cost: 2,
                m_cost: 64,
                p_cost: 1,
                file_base_nonce: [3; 24],
                hdr_cipher_id: 2,
                pld_cipher_id: 3,
            },
            password_slots: vec![PasswordSlot { nonce: [4; 12], wrapped_dek: [5; 48], check: [6; 32] }],
            hybrid_keyslots: vec![],
            hybrid_keyslots_1024: vec![],
            protected_meta: vec![7; META_NONCE_LEN + META_TLV_MANDATORY_PT_LEN + AEAD_TAG],
            sender: Some(SenderInfo { name: "alice".into(), x25519_pk: [8; 32], mlkem_pk: [9; 1184] }),
            mac: [10; 32],
        }
    }

    #[test]
    fn header_roundtrip_and_size() {
        let h = sample();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), h.total_size());
        let p = Header::parse(&bytes).unwrap();
        assert_eq!(p.to_bytes(), bytes);
        assert_eq!(p.public.header_total_size as usize, bytes.len());
        assert_eq!(p.sender.unwrap().name, "alice");
    }

    #[test]
    fn minimal_header_has_the_documented_size() {
        let mut h = sample();
        h.password_slots.clear();
        h.sender = None;
        assert_eq!(h.to_bytes().len(), MIN_HEADER_TOTAL_SIZE);
        // The figures quoted in FORMAT.md.
        assert_eq!(MIN_HEADER_TOTAL_SIZE, 155);
        assert_eq!(MIN_HEADER_TOTAL_SIZE + PASSWORD_SLOT_LEN, 247);
        assert_eq!((PASSWORD_SLOT_LEN, ASYM_KEYSLOT_LEN, ASYM_1024_KEYSLOT_LEN), (92, 1180, 1660));
    }

    #[test]
    fn every_truncation_and_extension_is_rejected() {
        let bytes = sample().to_bytes();
        for cut in 0..bytes.len() {
            assert!(Header::parse(&bytes[..cut]).is_err(), "accepted a header cut at {cut}");
        }
        let mut longer = bytes;
        longer.push(0);
        assert!(Header::parse(&longer).is_err());
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let s = "é".repeat(200); // 400 bytes
        let cut = truncate_text(&s);
        assert_eq!(cut.len(), 254);
        assert!(cut.chars().all(|c| c == 'é'));

        let env = EnvelopeContent {
            block_size_id: 1,
            filename: Some("a".repeat(1000)),
            comment: Some(s),
            ..EnvelopeContent::default()
        };
        let back = deserialize_meta_tlv(&serialize_meta_tlv(&env)).unwrap();
        assert_eq!(back.filename.unwrap().len(), 255);
        assert_eq!(back.comment.unwrap().len(), 254);
    }

    #[test]
    fn metadata_length_does_not_depend_on_the_size_value() {
        let a = EnvelopeContent { block_size_id: 1, ..EnvelopeContent::default() };
        let b = EnvelopeContent { original_size: u64::MAX, ..a.clone() };
        assert_eq!(serialize_meta_tlv(&a).len(), META_TLV_MANDATORY_PT_LEN);
        assert_eq!(serialize_meta_tlv(&a).len(), serialize_meta_tlv(&b).len());
    }

    #[test]
    fn unknown_metadata_fields_follow_the_critical_rule() {
        let mut tlv = serialize_meta_tlv(&EnvelopeContent { block_size_id: 1, ..EnvelopeContent::default() });
        let mut ignorable = tlv.clone();
        ignorable.extend_from_slice(&[0x90, 1, 0]);
        assert!(deserialize_meta_tlv(&ignorable).is_ok());
        tlv.extend_from_slice(&[0x20, 1, 0]);
        assert!(deserialize_meta_tlv(&tlv).is_err());
        // Unknown compression algorithm.
        let mut bad_algo = serialize_meta_tlv(&EnvelopeContent { block_size_id: 1, ..EnvelopeContent::default() });
        bad_algo.extend_from_slice(&[tlv_tags::COMPRESS_ALGO_ID, 1, 0x02]);
        assert!(deserialize_meta_tlv(&bad_algo).is_err());
    }
}
