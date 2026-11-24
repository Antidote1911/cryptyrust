//! Arsenic V2 encryption, decryption and header maintenance.
//!
//! Key hierarchy
//! -------------
//! * A random 32-byte **DEK** per file. Every key slot wraps that same DEK.
//! * Password slot: `master = Argon2id(NFC(password), salt)`, then two
//!   independent subkeys — one wraps the DEK, one produces the slot's check
//!   tag. All password slots of a file share the salt, so trying a password
//!   costs a single Argon2id run whatever the number of slots.
//! * Hybrid slot: X25519 + ML-KEM shared secrets hashed into a wrapping key.
//! * From the DEK: header MAC key, metadata key, payload key.
//!
//! Integrity
//! ---------
//! * `HeaderMAC` (keyed by the DEK) covers the whole header.
//! * Payload blocks are independent AEAD messages. Index and a *final block*
//!   flag are bound into both nonce and AAD, so reordering, truncation and
//!   extension all fail authentication — in a single pass over the file.

// Lint exemptions for this module — none of them hides a reachable failure:
//  * expect: OS randomness (no recovery) and fixed-size conversions.
//  * casts: sizes bounded by the format and progress percentages.
#![allow(
    clippy::expect_used, clippy::missing_panics_doc,
    clippy::cast_possible_truncation, clippy::cast_precision_loss, clippy::cast_sign_loss,
)]

use std::io::{Read, Seek, SeekFrom, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::fill as os_fill;
use rayon::prelude::*;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::errors::CoreErr;
use crate::secret::Secret;
use crate::Ui;

use super::cipher_dispatch;
use super::header::{
    deserialize_meta_tlv, serialize_meta_tlv, EnvelopeContent, EnvelopeMetadata, Header,
    HybridKeyslot, HybridKeyslot1024, PasswordSlot, PublicHeader, SenderInfo, AEAD_TAG,
    COMPRESS_ZSTD, HEADER_MAC_LEN, HEADER_SIZE_OFFSET, MAGIC, MAX_ASYM_KEYSLOTS,
    MAX_PASSWORD_SLOTS, META_NONCE_LEN, MIN_HEADER_TOTAL_SIZE, VERSION, WRAPPED_DEK_LEN,
};
use super::hybrid_kem;
use super::{
    CipherId, HybridRecipient, KemLevel, BLOCK_ID_32MB, BLOCK_ID_4MB, BLOCK_SIZE_32MB,
    BLOCK_SIZE_4MB, LARGE_FILE_THRESHOLD, MAX_ARGON2_RAM_KB, MAX_HEADER_TOTAL_SIZE, MAX_P_COST,
    MAX_T_COST,
};

type Dek = Secret<[u8; 32]>;

// ── Domain separation ─────────────────────────────────────────────────────────

const CTX_PW_WRAP_KEY: &str = "Arsenic V2 password slot wrapping key";
const CTX_PW_CHECK_KEY: &str = "Arsenic V2 password slot check key";
const CTX_HEADER_MAC_KEY: &str = "Arsenic V2 header MAC key";
const CTX_META_KEY: &str = "Arsenic V2 metadata key";
const CTX_PAYLOAD_KEY: &str = "Arsenic V2 payload key";
const CTX_BLOCK_NONCE: &str = "Arsenic V2 block nonce";
const CTX_HYBRID_768: &str = "Arsenic V2 hybrid KEM 768";
const CTX_HYBRID_1024: &str = "Arsenic V2 hybrid KEM 1024";

const AAD_PASSWORD_WRAPPED_DEK: &[u8] = b"arsenic-v2-password-wrapped-dek";
const AAD_HYBRID_WRAPPED_DEK: &[u8] = b"arsenic-v2-hybrid-wrapped-dek";
const AAD_PROTECTED_META: &[u8] = b"arsenic-v2-protected-meta";

/// Plaintext held in memory at once while (de)crypting blocks in parallel.
const WINDOW_BYTES: usize = 128 * 1024 * 1024;
/// zstd levels accepted when encrypting.
const ZSTD_LEVELS: std::ops::RangeInclusive<i32> = 1..=22;

// ── Small helpers ─────────────────────────────────────────────────────────────

/// Fill a fixed-size array with bytes from the OS CSPRNG (no PRNG layer).
fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    os_fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

fn read_full(reader: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut nread = 0;
    while nread < buf.len() {
        match reader.read(&mut buf[nread..]) {
            Ok(0) => break,
            Ok(n) => nread += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(nread)
}

fn tampered(what: &str) -> CoreErr {
    CoreErr::DecryptFail(format!("{what} authentication failed — the file is corrupted or was modified."))
}

/// Check Argon2id parameters against the format limits. Used before running
/// the KDF on a file's (untrusted) parameters, and when encrypting so that a
/// file that could never be decrypted is not produced.
fn validate_kdf_params(t_cost: u32, m_cost: u32, p_cost: u32) -> Result<(), String> {
    if t_cost == 0 || t_cost > MAX_T_COST {
        return Err(format!("t_cost {t_cost} out of range [1, {MAX_T_COST}]"));
    }
    if p_cost == 0 || p_cost > MAX_P_COST {
        return Err(format!("p_cost {p_cost} out of range [1, {MAX_P_COST}]"));
    }
    let min_m = 8 * p_cost;
    if !(min_m..=MAX_ARGON2_RAM_KB).contains(&m_cost) {
        return Err(format!("m_cost {m_cost} KiB out of range [{min_m}, {MAX_ARGON2_RAM_KB}]"));
    }
    Ok(())
}

const fn select_block_params(filesize: u64) -> (usize, u8) {
    if filesize < LARGE_FILE_THRESHOLD {
        (BLOCK_SIZE_4MB, BLOCK_ID_4MB)
    } else {
        (BLOCK_SIZE_32MB, BLOCK_ID_32MB)
    }
}

fn block_size_from_id(id: u8) -> Result<usize, CoreErr> {
    match id {
        BLOCK_ID_4MB => Ok(BLOCK_SIZE_4MB),
        BLOCK_ID_32MB => Ok(BLOCK_SIZE_32MB),
        _ => Err(CoreErr::DecryptFail(format!("Unknown block size ID: {id:#x}"))),
    }
}

/// Number of blocks processed together: one per thread, within the memory window.
fn window_len(block_size: usize) -> usize {
    rayon::current_num_threads().min(WINDOW_BYTES / block_size).max(1)
}

// ── Password slots ────────────────────────────────────────────────────────────

/// The two subkeys derived from a password.
struct PasswordKeys {
    wrap: Secret<[u8; 32]>,
    check: Secret<[u8; 32]>,
}

/// `Argon2id(NFC(password), salt)` split into two independent subkeys.
///
/// The password is normalized to Unicode NFC first: the same characters typed
/// on systems that compose accents differently give the same key.
fn derive_password_keys(password: &str, public: &PublicHeader) -> Result<PasswordKeys, CoreErr> {
    let params = Params::new(public.m_cost, public.t_cost, public.p_cost, Some(32))
        .map_err(|_| CoreErr::Argon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut normalized: String = password.nfc().collect();
    let mut master = [0u8; 32];
    let result = argon2.hash_password_into(normalized.as_bytes(), &public.salt, &mut master);
    normalized.zeroize();
    let keys = result.map(|()| PasswordKeys {
        wrap: Secret::new(blake3::derive_key(CTX_PW_WRAP_KEY, &master)),
        check: Secret::new(blake3::derive_key(CTX_PW_CHECK_KEY, &master)),
    });
    master.zeroize();
    keys.map_err(|_| CoreErr::Argon2Hash)
}

fn slot_check(keys: &PasswordKeys, nonce: &[u8; 12]) -> blake3::Hash {
    blake3::keyed_hash(keys.check.expose(), nonce)
}

/// True if `slot` was created with the password behind `keys` (constant time).
fn slot_matches(keys: &PasswordKeys, slot: &PasswordSlot) -> bool {
    slot_check(keys, &slot.nonce) == blake3::Hash::from(slot.check)
}

fn make_password_slot(
    hdr_cipher: CipherId,
    keys: &PasswordKeys,
    dek: &Dek,
) -> Result<PasswordSlot, CoreErr> {
    let nonce: [u8; 12] = random_array();
    let wrapped = cipher_dispatch::envelope_encrypt(
        hdr_cipher, keys.wrap.expose(), &nonce, AAD_PASSWORD_WRAPPED_DEK, dek.expose(),
    )?;
    Ok(PasswordSlot {
        nonce,
        wrapped_dek: to_wrapped(&wrapped)?,
        check: *slot_check(keys, &nonce).as_bytes(),
    })
}

fn to_wrapped(bytes: &[u8]) -> Result<[u8; WRAPPED_DEK_LEN], CoreErr> {
    bytes.try_into().map_err(|_| CoreErr::EncryptFail("unexpected wrapped key length".into()))
}

fn to_dek(mut plain: Vec<u8>) -> Option<Dek> {
    let dek = <[u8; 32]>::try_from(plain.as_slice()).ok().map(Secret::new);
    plain.zeroize();
    dek
}

/// Find the slot belonging to this password and unwrap the DEK.
/// Returns the slot index, or `DecryptionError` if the password matches none.
fn open_password_slots(
    hdr_cipher: CipherId,
    keys: &PasswordKeys,
    slots: &[PasswordSlot],
) -> Result<(usize, Dek), CoreErr> {
    for (i, slot) in slots.iter().enumerate() {
        if !slot_matches(keys, slot) {
            continue;
        }
        let dek = cipher_dispatch::envelope_decrypt(
            hdr_cipher, keys.wrap.expose(), &slot.nonce, AAD_PASSWORD_WRAPPED_DEK, &slot.wrapped_dek,
        )
        .ok()
        .and_then(to_dek);
        if let Some(dek) = dek {
            return Ok((i, dek));
        }
    }
    Err(CoreErr::DecryptionError)
}

// ── Hybrid keyslots ───────────────────────────────────────────────────────────

/// Hash both shared secrets and the public values of the exchange into the
/// key that wraps the DEK.
fn hybrid_wrapping_key(
    context: &str,
    eph_x25519_pk: &[u8; 32],
    mlkem_ct: &[u8],
    ss_x25519: &[u8; 32],
    ss_mlkem: &mut [u8; 32],
) -> Secret<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(eph_x25519_pk);
    hasher.update(mlkem_ct);
    hasher.update(ss_x25519);
    hasher.update(ss_mlkem.as_slice());
    ss_mlkem.zeroize();
    Secret::new(*hasher.finalize().as_bytes())
}

fn invalid_recipient_key() -> CoreErr {
    CoreErr::EncryptFail("a recipient has an invalid ML-KEM public key".into())
}

/// Fresh X25519 ephemeral: `(public key, shared secret with the recipient)`.
fn x25519_ephemeral(recipient_pk: &[u8; 32]) -> ([u8; 32], x25519_dalek::SharedSecret) {
    let mut seed: [u8; 32] = random_array();
    let secret = X25519StaticSecret::from(seed);
    seed.zeroize();
    let public = X25519PublicKey::from(&secret);
    (*public.as_bytes(), secret.diffie_hellman(&X25519PublicKey::from(*recipient_pk)))
}

fn wrap_for_hybrid(
    hdr_cipher: CipherId,
    wrapping_key: &Secret<[u8; 32]>,
    dek: &Dek,
) -> Result<([u8; 12], [u8; WRAPPED_DEK_LEN]), CoreErr> {
    let kek_nonce: [u8; 12] = random_array();
    let wrapped = cipher_dispatch::envelope_encrypt(
        hdr_cipher, wrapping_key.expose(), &kek_nonce, AAD_HYBRID_WRAPPED_DEK, dek.expose(),
    )?;
    Ok((kek_nonce, to_wrapped(&wrapped)?))
}

/// Wrap the DEK for one hybrid (X25519 + ML-KEM-768) recipient.
fn wrap_dek_hybrid(
    hdr_cipher: CipherId,
    recipient: &HybridRecipient,
    dek: &Dek,
) -> Result<HybridKeyslot, CoreErr> {
    let (ephemeral_x25519, ss_x25519) = x25519_ephemeral(&recipient.x25519);
    let mut m: [u8; 32] = random_array();
    let encaps = hybrid_kem::encaps_768(&recipient.mlkem, &m);
    m.zeroize();
    let (mlkem_ct, mut ss_mlkem) = encaps.ok_or_else(invalid_recipient_key)?;
    let key = hybrid_wrapping_key(
        CTX_HYBRID_768, &ephemeral_x25519, &mlkem_ct, ss_x25519.as_bytes(), &mut ss_mlkem,
    );
    let (kek_nonce, wrapped_dek) = wrap_for_hybrid(hdr_cipher, &key, dek)?;
    Ok(HybridKeyslot { ephemeral_x25519, mlkem_ct, kek_nonce, wrapped_dek })
}

/// Wrap the DEK for one hybrid (X25519 + ML-KEM-1024) recipient.
fn wrap_dek_hybrid_1024(
    hdr_cipher: CipherId,
    recipient: &HybridRecipient,
    dek: &Dek,
) -> Result<HybridKeyslot1024, CoreErr> {
    let ek_1024 = recipient.mlkem_1024.ok_or_else(|| {
        CoreErr::EncryptFail("a recipient has no ML-KEM-1024 key (public key only known at level 768)".into())
    })?;
    let (ephemeral_x25519, ss_x25519) = x25519_ephemeral(&recipient.x25519);
    let mut m: [u8; 32] = random_array();
    let encaps = hybrid_kem::encaps_1024(&ek_1024, &m);
    m.zeroize();
    let (mlkem_ct, mut ss_mlkem) = encaps.ok_or_else(invalid_recipient_key)?;
    let key = hybrid_wrapping_key(
        CTX_HYBRID_1024, &ephemeral_x25519, &mlkem_ct, ss_x25519.as_bytes(), &mut ss_mlkem,
    );
    let (kek_nonce, wrapped_dek) = wrap_for_hybrid(hdr_cipher, &key, dek)?;
    Ok(HybridKeyslot1024 { ephemeral_x25519, mlkem_ct, kek_nonce, wrapped_dek })
}

/// A hybrid private keypair: X25519 key + independent ML-KEM seed.
pub struct HybridPrivKey<'a> {
    pub x25519_sk: &'a [u8; 32],
    pub mlkem_seed: &'a [u8; 64],
}

fn unwrap_hybrid_slot(
    hdr_cipher: CipherId,
    key: &Secret<[u8; 32]>,
    kek_nonce: &[u8; 12],
    wrapped_dek: &[u8; WRAPPED_DEK_LEN],
) -> Option<Dek> {
    cipher_dispatch::envelope_decrypt(hdr_cipher, key.expose(), kek_nonce, AAD_HYBRID_WRAPPED_DEK, wrapped_dek)
        .ok()
        .and_then(to_dek)
}

/// Try every hybrid keyslot (768 then 1024) with this keypair.
///
/// Returns the slot position — 768 slots first, then 1024 slots, the same
/// numbering as [`list_recipients`] — and the DEK.
fn open_hybrid_slots(
    hdr_cipher: CipherId,
    key: &HybridPrivKey<'_>,
    header: &Header,
) -> Result<(usize, Dek), CoreErr> {
    let secret = X25519StaticSecret::from(*key.x25519_sk);
    for (i, slot) in header.hybrid_keyslots.iter().enumerate() {
        let ss_x25519 = secret.diffie_hellman(&X25519PublicKey::from(slot.ephemeral_x25519));
        let mut ss_mlkem = hybrid_kem::decaps_768(key.mlkem_seed, &slot.mlkem_ct);
        let wk = hybrid_wrapping_key(
            CTX_HYBRID_768, &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &mut ss_mlkem,
        );
        if let Some(dek) = unwrap_hybrid_slot(hdr_cipher, &wk, &slot.kek_nonce, &slot.wrapped_dek) {
            return Ok((i, dek));
        }
    }
    let offset = header.hybrid_keyslots.len();
    for (i, slot) in header.hybrid_keyslots_1024.iter().enumerate() {
        let ss_x25519 = secret.diffie_hellman(&X25519PublicKey::from(slot.ephemeral_x25519));
        let mut ss_mlkem = hybrid_kem::decaps_1024(key.mlkem_seed, &slot.mlkem_ct);
        let wk = hybrid_wrapping_key(
            CTX_HYBRID_1024, &slot.ephemeral_x25519, &slot.mlkem_ct, ss_x25519.as_bytes(), &mut ss_mlkem,
        );
        if let Some(dek) = unwrap_hybrid_slot(hdr_cipher, &wk, &slot.kek_nonce, &slot.wrapped_dek) {
            return Ok((offset + i, dek));
        }
    }
    Err(CoreErr::NoAsymKeyFound)
}

// ── Keys derived from the DEK ─────────────────────────────────────────────────

fn subkey(context: &str, dek: &Dek) -> Secret<[u8; 32]> {
    Secret::new(blake3::derive_key(context, dek.expose()))
}

fn header_mac(dek: &Dek, signed_bytes: &[u8]) -> blake3::Hash {
    blake3::keyed_hash(subkey(CTX_HEADER_MAC_KEY, dek).expose(), signed_bytes)
}

/// Compute the `HeaderMAC` and return the serialized header.
fn seal_header(header: &mut Header, dek: &Dek) -> Result<Vec<u8>, CoreErr> {
    if header.total_size() > MAX_HEADER_TOTAL_SIZE as usize {
        return Err(CoreErr::EncryptFail("Header too large (too many key slots)".into()));
    }
    let mut bytes = header.signed_bytes();
    header.public.header_total_size = (bytes.len() + HEADER_MAC_LEN) as u32;
    header.mac = *header_mac(dek, &bytes).as_bytes();
    bytes.extend_from_slice(&header.mac);
    Ok(bytes)
}

fn encrypt_meta(hdr_cipher: CipherId, dek: &Dek, info: &EnvelopeContent) -> Result<Vec<u8>, CoreErr> {
    let nonce: [u8; META_NONCE_LEN] = random_array();
    let ct = cipher_dispatch::envelope_encrypt(
        hdr_cipher, subkey(CTX_META_KEY, dek).expose(), &nonce, AAD_PROTECTED_META, &serialize_meta_tlv(info),
    )?;
    let mut out = Vec::with_capacity(META_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_meta(hdr_cipher: CipherId, dek: &Dek, protected: &[u8]) -> Result<EnvelopeContent, CoreErr> {
    let (nonce, ct) = protected.split_at(META_NONCE_LEN);
    let nonce: [u8; META_NONCE_LEN] = nonce.try_into().expect("split at META_NONCE_LEN");
    let tlv = cipher_dispatch::envelope_decrypt(
        hdr_cipher, subkey(CTX_META_KEY, dek).expose(), &nonce, AAD_PROTECTED_META, ct,
    )
    .map_err(|_| tampered("Metadata"))?;
    deserialize_meta_tlv(&tlv)
}

// ── Payload blocks ────────────────────────────────────────────────────────────

/// Everything needed to (de)crypt the blocks of one file.
struct Payload<'a> {
    cipher: CipherId,
    key: &'a Secret<[u8; 32]>,
    base_nonce: &'a [u8; 24],
    block_size: usize,
}

impl Payload<'_> {
    /// Per-block key, nonce and AAD. The final flag is part of nonce and AAD:
    /// a block cannot be moved, and a non-final block cannot end the file.
    fn block_params(&self, index: u64, is_final: bool) -> ([u8; 32], [u8; 24], [u8; 9]) {
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&index.to_le_bytes());
        aad[8] = u8::from(is_final);
        let key = *blake3::keyed_hash(self.key.expose(), &index.to_le_bytes()).as_bytes();
        let mut material = [0u8; 24 + 9];
        material[..24].copy_from_slice(self.base_nonce);
        material[24..].copy_from_slice(&aad);
        let hash = blake3::derive_key(CTX_BLOCK_NONCE, &material);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hash[..24]);
        (key, nonce, aad)
    }

    fn encrypt_block(&self, index: u64, is_final: bool, plaintext: &[u8]) -> Result<Vec<u8>, CoreErr> {
        let (mut key, nonce, aad) = self.block_params(index, is_final);
        let out = cipher_dispatch::block_encrypt(self.cipher, &key, &nonce, &aad, plaintext);
        key.zeroize();
        out
    }

    fn decrypt_block(&self, index: u64, is_final: bool, ciphertext: &[u8]) -> Result<Vec<u8>, CoreErr> {
        let (mut key, nonce, aad) = self.block_params(index, is_final);
        let out = cipher_dispatch::block_decrypt(self.cipher, &key, &nonce, &aad, ciphertext);
        key.zeroize();
        out.map_err(|_| tampered("Payload"))
    }

    /// Encrypt `input` to `output`, a window of blocks at a time in parallel.
    ///
    /// One block is always held back until it is known whether more data
    /// follows, so the last block — and only it — carries the final flag. An
    /// empty input still produces one (empty) final block.
    fn encrypt(
        &self,
        input: &mut dyn Read,
        output: &mut dyn Write,
        ui: &dyn Ui,
        size_hint: u64,
    ) -> Result<(), CoreErr> {
        let window = window_len(self.block_size);
        let mut pending: Option<Vec<u8>> = None;
        let mut eof = false;
        let mut index: u64 = 0;
        let mut done: u64 = 0;

        while !eof {
            if ui.is_cancelled() {
                return Err(CoreErr::Cancelled);
            }
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(window + 1);
            batch.extend(pending.take());
            while !eof && batch.len() <= window {
                let mut block = vec![0u8; self.block_size];
                let n = read_full(input, &mut block)?;
                block.truncate(n);
                eof = n < self.block_size;
                // A zero-length read only makes a block for an empty file.
                if n > 0 || (batch.is_empty() && index == 0) {
                    batch.push(block);
                }
            }
            if !eof {
                pending = batch.pop();
            }

            let last = batch.len().saturating_sub(1);
            let encrypted: Result<Vec<Vec<u8>>, CoreErr> = batch
                .par_iter()
                .enumerate()
                .map(|(k, pt)| self.encrypt_block(index + k as u64, eof && k == last, pt))
                .collect();
            for block in &mut batch {
                done += block.len() as u64;
                block.zeroize();
            }
            for ct in encrypted? {
                output.write_all(&ct)?;
            }
            index += batch.len() as u64;

            let pct = (done as f32 / size_hint.max(1) as f32 * 95.0) as i32;
            ui.output(pct.clamp(0, 95));
        }
        Ok(())
    }

    /// Decrypt `payload_len` bytes of blocks from `input` to `output`.
    ///
    /// The number of blocks follows from the payload length; the last one must
    /// authenticate as final, which detects truncation at a block boundary.
    fn decrypt(
        &self,
        input: &mut dyn Read,
        output: &mut dyn Write,
        ui: &dyn Ui,
        payload_len: u64,
    ) -> Result<(), CoreErr> {
        let (num_blocks, last_len) = self.layout(payload_len)?;
        let full = self.block_size + AEAD_TAG;
        let window = window_len(self.block_size) as u64;

        let mut index: u64 = 0;
        while index < num_blocks {
            if ui.is_cancelled() {
                return Err(CoreErr::Cancelled);
            }
            let count = window.min(num_blocks - index);
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
            for k in 0..count {
                let len = if index + k + 1 == num_blocks { last_len } else { full };
                let mut block = vec![0u8; len];
                if read_full(input, &mut block)? != len {
                    return Err(tampered("Payload"));
                }
                batch.push(block);
            }
            let decrypted: Result<Vec<Vec<u8>>, CoreErr> = batch
                .par_iter()
                .enumerate()
                .map(|(k, ct)| {
                    let i = index + k as u64;
                    self.decrypt_block(i, i + 1 == num_blocks, ct)
                })
                .collect();
            for mut pt in decrypted? {
                let written = output.write_all(&pt);
                pt.zeroize();
                written?;
            }
            index += count;

            let pct = (index as f32 / num_blocks as f32 * 95.0) as i32;
            ui.output(pct.clamp(0, 95));
        }
        Ok(())
    }

    /// `(number of blocks, encrypted length of the last one)` for a payload.
    fn layout(&self, payload_len: u64) -> Result<(u64, usize), CoreErr> {
        let full = (self.block_size + AEAD_TAG) as u64;
        let num_blocks = payload_len.div_ceil(full);
        // There is always at least one block, and every block has a tag.
        let last_len = num_blocks
            .checked_sub(1)
            .map(|n| payload_len - n * full)
            .filter(|&l| l >= AEAD_TAG as u64)
            .ok_or_else(|| tampered("Payload"))?;
        Ok((num_blocks, last_len as usize))
    }
}

/// Counts the bytes read from the plaintext source.
struct CountingReader<'a> {
    inner: &'a mut dyn Read,
    count: u64,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// Refuses to write more than the size announced by the (authenticated)
/// metadata — this is what bounds a hostile compressed payload.
struct LimitWriter<'a> {
    inner: &'a mut dyn Write,
    remaining: u64,
}

impl Write for LimitWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decrypted data is larger than the size recorded in the file",
            ));
        }
        self.inner.write_all(buf)?;
        self.remaining -= buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ── Header reading ────────────────────────────────────────────────────────────

/// Read the raw header bytes from the current position of `input`.
fn read_header_bytes<R: Read>(input: &mut R) -> Result<Vec<u8>, CoreErr> {
    const PREFIX: usize = HEADER_SIZE_OFFSET + 4;
    let mut prefix = [0u8; PREFIX];
    input.read_exact(&mut prefix).map_err(|_| CoreErr::BadSignature)?;
    // Report a foreign or older file as such, before looking at anything else.
    if prefix[0..4] != MAGIC {
        return Err(CoreErr::BadSignature);
    }
    if prefix[4..6] != VERSION {
        return Err(CoreErr::BadHeaderVersion);
    }
    let size = u32::from_le_bytes(prefix[HEADER_SIZE_OFFSET..].try_into().expect("4 bytes")) as usize;
    if !(MIN_HEADER_TOTAL_SIZE..=MAX_HEADER_TOTAL_SIZE as usize).contains(&size) {
        return Err(CoreErr::DecryptFail(format!("header size {size} out of range")));
    }
    let mut raw = vec![0u8; size];
    raw[..PREFIX].copy_from_slice(&prefix);
    input.read_exact(&mut raw[PREFIX..]).map_err(|_| CoreErr::BadSignature)?;
    Ok(raw)
}

/// Read and parse the header without any key. Nothing in it is authenticated
/// until the file is opened with a password or a keypair.
pub fn read_header<R: Read>(input: &mut R) -> Result<Header, CoreErr> {
    Header::parse(&read_header_bytes(input)?)
}

/// A header whose MAC and metadata were verified with the DEK.
struct Opened {
    header: Header,
    hdr_cipher: CipherId,
    pld_cipher: CipherId,
    dek: Dek,
    info: EnvelopeContent,
}

impl Opened {
    fn new(raw: &[u8], header: Header, dek: Dek) -> Result<Self, CoreErr> {
        let signed = &raw[..raw.len() - HEADER_MAC_LEN];
        if header_mac(&dek, signed) != blake3::Hash::from(header.mac) {
            return Err(tampered("Header"));
        }
        let hdr_cipher = CipherId::from_byte(header.public.hdr_cipher_id)?;
        let pld_cipher = CipherId::from_byte(header.public.pld_cipher_id)?;
        let info = decrypt_meta(hdr_cipher, &dek, &header.protected_meta)?;
        Ok(Self { header, hdr_cipher, pld_cipher, dek, info })
    }

    /// Open with a password. Also returns the password's subkeys and the index
    /// of its slot, for the operations that edit the slot list.
    fn with_password<R: Read>(
        input: &mut R,
        password: &Secret<String>,
    ) -> Result<(Self, PasswordKeys, usize), CoreErr> {
        let raw = read_header_bytes(input)?;
        let header = Header::parse(&raw)?;
        let hdr_cipher = CipherId::from_byte(header.public.hdr_cipher_id)?;
        if header.password_slots.is_empty() {
            return Err(CoreErr::DecryptFail(
                "this file has no password — it can only be opened with a keypair.".into(),
            ));
        }
        let p = &header.public;
        validate_kdf_params(p.t_cost, p.m_cost, p.p_cost).map_err(CoreErr::DecryptFail)?;
        let keys = derive_password_keys(password.expose(), p)?;
        let (slot, dek) = open_password_slots(hdr_cipher, &keys, &header.password_slots)?;
        Ok((Self::new(&raw, header, dek)?, keys, slot))
    }

    /// Open with a hybrid keypair. Also returns the index of the slot used.
    fn with_key<R: Read>(input: &mut R, key: &HybridPrivKey<'_>) -> Result<(Self, usize), CoreErr> {
        let raw = read_header_bytes(input)?;
        let header = Header::parse(&raw)?;
        let hdr_cipher = CipherId::from_byte(header.public.hdr_cipher_id)?;
        let (slot, dek) = open_hybrid_slots(hdr_cipher, key, &header)?;
        Ok((Self::new(&raw, header, dek)?, slot))
    }

    fn payload<'a>(&'a self, key: &'a Secret<[u8; 32]>) -> Result<Payload<'a>, CoreErr> {
        Ok(Payload {
            cipher: self.pld_cipher,
            key,
            base_nonce: &self.header.public.file_base_nonce,
            block_size: block_size_from_id(self.info.block_size_id)?,
        })
    }

    /// Offset of the first payload byte.
    fn payload_start(&self) -> u64 {
        u64::from(self.header.public.header_total_size)
    }

    /// Decrypt the whole payload to `output`.
    fn decrypt_to<R: Read + Seek, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        ui: &dyn Ui,
    ) -> Result<EnvelopeMetadata, CoreErr> {
        let payload_key = subkey(CTX_PAYLOAD_KEY, &self.dek);
        let payload = self.payload(&payload_key)?;
        let start = self.payload_start();
        let payload_len = input.seek(SeekFrom::End(0))?.saturating_sub(start);
        input.seek(SeekFrom::Start(start))?;

        let mut limited = LimitWriter { inner: output, remaining: self.info.original_size };
        if self.info.compress_algo.is_some() {
            // Streaming decompression, capped by `LimitWriter`.
            let mut decoder = zstd::stream::write::Decoder::new(&mut limited)?;
            payload.decrypt(input, &mut decoder, ui, payload_len)?;
            decoder.flush()?;
        } else {
            payload.decrypt(input, &mut limited, ui, payload_len)?;
        }
        if limited.remaining != 0 {
            return Err(CoreErr::DecryptFail(
                "decrypted size does not match the size recorded in the file.".into(),
            ));
        }
        output.flush()?;
        ui.output(100);
        Ok(self.info.metadata())
    }

    /// Decrypt one block by index (uncompressed files only).
    fn decrypt_block<R: Read + Seek>(&self, input: &mut R, block_index: u64) -> Result<Vec<u8>, CoreErr> {
        if self.info.compress_algo.is_some() {
            return Err(CoreErr::DecryptFail(
                "Random-access decryption is not supported for compressed files".into(),
            ));
        }
        let payload_key = subkey(CTX_PAYLOAD_KEY, &self.dek);
        let payload = self.payload(&payload_key)?;
        let start = self.payload_start();
        let payload_len = input.seek(SeekFrom::End(0))?.saturating_sub(start);
        let (num_blocks, last_len) = payload.layout(payload_len)?;
        if block_index >= num_blocks {
            return Err(CoreErr::DecryptFail(format!(
                "block_index {block_index} out of range [0, {num_blocks})"
            )));
        }
        let full = payload.block_size + AEAD_TAG;
        let is_final = block_index + 1 == num_blocks;
        let mut block = vec![0u8; if is_final { last_len } else { full }];
        input.seek(SeekFrom::Start(start + block_index * full as u64))?;
        if read_full(input, &mut block)? != block.len() {
            return Err(tampered("Payload"));
        }
        payload.decrypt_block(block_index, is_final, &block)
    }
}

// ── Public encrypt ────────────────────────────────────────────────────────────

/// Encrypt `input` to `output` in the Arsenic V2 format.
///
/// * A non-empty `password` creates a password slot; an empty one creates
///   none, which requires at least one recipient in `params`.
/// * `filesize` is only a hint (block size choice and progress).
/// * Every check and the Argon2id run happen **before** the payload is
///   written; the header is completed with a single seek back at the end.
///
/// Memory: a window of blocks (at most 128 MiB of plaintext), with or without
/// compression.
pub fn encrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
    params: &super::ArsenicParams,
) -> Result<(), CoreErr>
where
    R: Read,
    W: Write + Seek,
{
    // ── Validate everything first ─────────────────────────────────────────
    validate_kdf_params(params.t_cost, params.m_cost, params.p_cost).map_err(CoreErr::EncryptFail)?;
    if let Some(level) = params.compress {
        if !ZSTD_LEVELS.contains(&level) {
            return Err(CoreErr::EncryptFail(format!("compression level {level} out of range [1, 22]")));
        }
    }
    let has_password = !password.expose().is_empty();
    if !has_password && params.recipients.is_empty() {
        return Err(CoreErr::EncryptFail("a password or at least one recipient is required".into()));
    }
    if params.recipients.len() > MAX_ASYM_KEYSLOTS {
        return Err(CoreErr::EncryptFail(format!("too many recipients (max {MAX_ASYM_KEYSLOTS})")));
    }
    ui.output(0);

    // ── Keys and key slots ────────────────────────────────────────────────
    let dek: Dek = Secret::new(random_array());
    let (block_size, block_size_id) = select_block_params(filesize);
    let public = PublicHeader {
        header_total_size: 0,
        salt: random_array(),
        t_cost: params.t_cost,
        m_cost: params.m_cost,
        p_cost: params.p_cost,
        file_base_nonce: random_array(),
        hdr_cipher_id: params.hdr_cipher.to_byte(),
        pld_cipher_id: params.pld_cipher.to_byte(),
    };

    let mut password_slots = Vec::new();
    if has_password {
        let keys = derive_password_keys(password.expose(), &public)?;
        password_slots.push(make_password_slot(params.hdr_cipher, &keys, &dek)?);
    }
    let mut hybrid_keyslots = Vec::new();
    let mut hybrid_keyslots_1024 = Vec::new();
    for recipient in &params.recipients {
        match params.kem_level {
            KemLevel::L768 => hybrid_keyslots.push(wrap_dek_hybrid(params.hdr_cipher, recipient, &dek)?),
            KemLevel::L1024 => {
                hybrid_keyslots_1024.push(wrap_dek_hybrid_1024(params.hdr_cipher, recipient, &dek)?);
            }
        }
    }

    let sender = match (&params.sender_name, &params.sender_x25519_pk, &params.sender_mlkem_pk) {
        (Some(name), Some(x25519_pk), Some(mlkem_pk)) => {
            Some(SenderInfo { name: name.clone(), x25519_pk: *x25519_pk, mlkem_pk: *mlkem_pk })
        }
        _ => None,
    };

    // The metadata length does not depend on the final size, so the header
    // size is known now and a placeholder can be written.
    let mut info = EnvelopeContent {
        original_size: 0,
        block_size_id,
        compress_algo: params.compress.map(|_| COMPRESS_ZSTD),
        filename: params.metadata.filename.clone(),
        comment: params.metadata.comment.clone(),
        timestamp_secs: params.metadata.timestamp_secs,
    };
    let mut header = Header {
        public,
        password_slots,
        hybrid_keyslots,
        hybrid_keyslots_1024,
        protected_meta: vec![0u8; META_NONCE_LEN + serialize_meta_tlv(&info).len() + AEAD_TAG],
        sender,
        mac: [0u8; HEADER_MAC_LEN],
    };
    let header_size = header.total_size();
    if header_size > MAX_HEADER_TOTAL_SIZE as usize {
        return Err(CoreErr::EncryptFail("Header too large (too many recipients)".into()));
    }
    let start = output.stream_position()?;
    output.write_all(&vec![0u8; header_size])?;

    // ── Payload ───────────────────────────────────────────────────────────
    let payload_key = subkey(CTX_PAYLOAD_KEY, &dek);
    let payload = Payload {
        cipher: params.pld_cipher,
        key: &payload_key,
        base_nonce: &header.public.file_base_nonce,
        block_size,
    };
    let mut source = CountingReader { inner: input, count: 0 };
    if let Some(level) = params.compress {
        // Streaming compression: the encoder is just another reader.
        let mut encoder = zstd::stream::read::Encoder::new(&mut source, level)?;
        payload.encrypt(&mut encoder, output, ui, filesize)?;
    } else {
        payload.encrypt(&mut source, output, ui, filesize)?;
    }
    info.original_size = source.count;

    // ── Complete the header ───────────────────────────────────────────────
    header.protected_meta = encrypt_meta(params.hdr_cipher, &dek, &info)?;
    let header_bytes = seal_header(&mut header, &dek)?;
    debug_assert_eq!(header_bytes.len(), header_size);
    let end = output.stream_position()?;
    output.seek(SeekFrom::Start(start))?;
    output.write_all(&header_bytes)?;
    output.seek(SeekFrom::Start(end))?;
    output.flush()?;

    ui.output(100);
    Ok(())
}

/// Encrypt without requiring `Seek` on the output.
///
/// Buffers the whole ciphertext in memory before writing it; for large data
/// use [`encrypt_arsenic`] with a seekable output such as a `File`.
pub fn encrypt_arsenic_to_writer<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
    params: &super::ArsenicParams,
) -> Result<(), CoreErr> {
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    encrypt_arsenic(input, &mut buf, password, ui, filesize, params)?;
    output.write_all(buf.get_ref())?;
    output.flush()?;
    Ok(())
}

// ── Public decrypt ────────────────────────────────────────────────────────────

/// Decrypt an Arsenic file with a password.
///
/// Single pass: each window of blocks is authenticated, then written. If a
/// later block fails, the error is returned after the earlier plaintext was
/// written — the caller must discard the output on error.
pub fn decrypt_arsenic<R, W>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    _filesize: u64,
) -> Result<EnvelopeMetadata, CoreErr>
where
    R: Read + Seek,
    W: Write,
{
    let (opened, _, _) = Opened::with_password(input, password)?;
    opened.decrypt_to(input, output, ui)
}

/// Decrypt an Arsenic file with a hybrid keypair (X25519 + ML-KEM seed).
///
/// Returns `NoAsymKeyFound` if no keyslot matches. Same contract as
/// [`decrypt_arsenic`].
pub fn decrypt_arsenic_with_key<R, W>(
    input: &mut R,
    output: &mut W,
    x25519_privkey: &Secret<[u8; 32]>,
    mlkem_seed: &[u8; 64],
    ui: &dyn Ui,
    _filesize: u64,
) -> Result<EnvelopeMetadata, CoreErr>
where
    R: Read + Seek,
    W: Write,
{
    let key = HybridPrivKey { x25519_sk: x25519_privkey.expose(), mlkem_seed };
    let (opened, _) = Opened::with_key(input, &key)?;
    opened.decrypt_to(input, output, ui)
}

/// Decrypt a single block by index with a password.
///
/// The header and the block are authenticated; the rest of the file is not
/// read. The last block is recognised from the file length, so a truncated
/// file fails on its (new) last block, not on the earlier ones.
pub fn decrypt_block_at<R: Read + Seek>(
    input: &mut R,
    password: &Secret<String>,
    block_index: u64,
    _ui: &dyn Ui,
) -> Result<Vec<u8>, CoreErr> {
    let (opened, _, _) = Opened::with_password(input, password)?;
    opened.decrypt_block(input, block_index)
}

/// Decrypt a single block by index with a hybrid keypair.
pub fn decrypt_block_at_with_key<R: Read + Seek>(
    input: &mut R,
    x25519_sk: &Secret<[u8; 32]>,
    mlkem_seed: &[u8; 64],
    block_index: u64,
    _ui: &dyn Ui,
) -> Result<Vec<u8>, CoreErr> {
    let key = HybridPrivKey { x25519_sk: x25519_sk.expose(), mlkem_seed };
    let (opened, _) = Opened::with_key(input, &key)?;
    opened.decrypt_block(input, block_index)
}

// ── Key probing (no payload access) ───────────────────────────────────────────

/// Index into `keys` of the first keypair that opens a keyslot of the file.
pub fn find_decrypting_key<R: Read>(
    input: &mut R,
    keys: &[HybridPrivKey<'_>],
) -> Result<Option<usize>, CoreErr> {
    if keys.is_empty() {
        return Ok(None);
    }
    let header = read_header(input)?;
    if header.hybrid_keyslots.is_empty() && header.hybrid_keyslots_1024.is_empty() {
        return Ok(None);
    }
    let hdr_cipher = CipherId::from_byte(header.public.hdr_cipher_id)?;
    Ok(keys.iter().position(|key| open_hybrid_slots(hdr_cipher, key, &header).is_ok()))
}

/// Position of the keyslot this keypair opens, in the numbering of
/// [`list_recipients`] (768 slots first, then 1024 slots).
pub fn find_slot_for_privkey<R: Read>(
    input: &mut R,
    x25519_privkey: &[u8; 32],
    mlkem_seed: &[u8; 64],
) -> Result<Option<usize>, CoreErr> {
    let header = read_header(input)?;
    let hdr_cipher = CipherId::from_byte(header.public.hdr_cipher_id)?;
    let key = HybridPrivKey { x25519_sk: x25519_privkey, mlkem_seed };
    Ok(open_hybrid_slots(hdr_cipher, &key, &header).ok().map(|(slot, _)| slot))
}

/// Ephemeral public keys of every hybrid keyslot: the ML-KEM-768 slots first,
/// then the ML-KEM-1024 slots. They identify slots by position; they are not
/// the recipients' own public keys.
pub fn list_recipients<R: Read>(input: &mut R) -> Result<Vec<[u8; 32]>, CoreErr> {
    let header = read_header(input)?;
    Ok(header
        .hybrid_keyslots
        .iter()
        .map(|s| s.ephemeral_x25519)
        .chain(header.hybrid_keyslots_1024.iter().map(|s| s.ephemeral_x25519))
        .collect())
}

// ── Header maintenance ────────────────────────────────────────────────────────
//
// Every operation authenticates with a password of the file (any slot),
// verifies the whole header, edits the slot list and seals the header again
// with the DEK. The payload is never touched.

/// Authenticate with `password` and return the verified header for editing.
/// The reader is rewound first; the second value is the on-disk header size.
fn open_for_edit<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
) -> Result<(Opened, PasswordKeys, usize, usize), CoreErr> {
    file.seek(SeekFrom::Start(0))?;
    let (opened, keys, slot) = Opened::with_password(file, password)?;
    let old_size = opened.header.public.header_total_size as usize;
    Ok((opened, keys, slot, old_size))
}

/// Derive the subkeys of a password that is about to get a slot, refusing an
/// empty password and one that already has a slot in `slots`.
fn new_password_keys(
    password: &Secret<String>,
    public: &PublicHeader,
    slots: &[PasswordSlot],
) -> Result<PasswordKeys, CoreErr> {
    if password.expose().is_empty() {
        return Err(CoreErr::EncryptFail("the new password must not be empty".into()));
    }
    let keys = derive_password_keys(password.expose(), public)?;
    if slots.iter().any(|s| slot_matches(&keys, s)) {
        return Err(CoreErr::EncryptFail("this password already opens the file".into()));
    }
    Ok(keys)
}

/// Replace the slot of `old_password` by one for `new_password`, in place.
///
/// Other password slots, the keyslots, the metadata and the payload are
/// unchanged, and so is the DEK: someone who knew the old password **and**
/// kept a copy of the old file can still decrypt that copy.
pub fn rekey_arsenic<F>(
    file: &mut F,
    old_password: &Secret<String>,
    new_password: &Secret<String>,
    ui: &dyn Ui,
) -> Result<(), CoreErr>
where
    F: Read + Write + Seek,
{
    ui.output(0);
    let (mut opened, _, slot, old_size) = open_for_edit(file, old_password)?;
    let header = &mut opened.header;
    header.password_slots.remove(slot);
    let keys = new_password_keys(new_password, &header.public, &header.password_slots)?;
    header.password_slots.insert(slot, make_password_slot(opened.hdr_cipher, &keys, &opened.dek)?);

    let bytes = seal_header(header, &opened.dek)?;
    debug_assert_eq!(bytes.len(), old_size);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.flush()?;
    ui.output(100);
    Ok(())
}

/// Build a header with one more hybrid keyslot.
///
/// `level`: `None` follows the file — ML-KEM-1024 if it only has 1024 slots
/// and the recipient has a 1024 key, ML-KEM-768 otherwise.
///
/// Returns `(new_header_bytes, old_header_size)` so the caller can write the
/// new header followed by the unchanged payload.
pub fn build_header_with_added_recipient<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
    recipient: &HybridRecipient,
    level: Option<KemLevel>,
) -> Result<(Vec<u8>, usize), CoreErr> {
    let (mut opened, _, _, old_size) = open_for_edit(file, password)?;
    let header = &mut opened.header;
    if header.hybrid_keyslots.len() + header.hybrid_keyslots_1024.len() >= MAX_ASYM_KEYSLOTS {
        return Err(CoreErr::EncryptFail(format!("Maximum number of recipients ({MAX_ASYM_KEYSLOTS}) reached")));
    }
    let follows_1024 = header.hybrid_keyslots.is_empty()
        && !header.hybrid_keyslots_1024.is_empty()
        && recipient.mlkem_1024.is_some();
    let level = level.unwrap_or(if follows_1024 { KemLevel::L1024 } else { KemLevel::L768 });
    match level {
        KemLevel::L768 => {
            header.hybrid_keyslots.push(wrap_dek_hybrid(opened.hdr_cipher, recipient, &opened.dek)?);
        }
        KemLevel::L1024 => header
            .hybrid_keyslots_1024
            .push(wrap_dek_hybrid_1024(opened.hdr_cipher, recipient, &opened.dek)?),
    }
    Ok((seal_header(header, &opened.dek)?, old_size))
}

/// Build a header without the hybrid keyslot at `index`, in the numbering of
/// [`list_recipients`].
pub fn build_header_with_removed_recipient<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
    index: usize,
) -> Result<(Vec<u8>, usize), CoreErr> {
    let (mut opened, _, _, old_size) = open_for_edit(file, password)?;
    let header = &mut opened.header;
    let n_768 = header.hybrid_keyslots.len();
    let total = n_768 + header.hybrid_keyslots_1024.len();
    if index >= total {
        return Err(CoreErr::DecryptFail(format!(
            "Recipient index {index} out of range (file has {total} asymmetric keyslots)"
        )));
    }
    if index < n_768 {
        header.hybrid_keyslots.remove(index);
    } else {
        header.hybrid_keyslots_1024.remove(index - n_768);
    }
    Ok((seal_header(header, &opened.dek)?, old_size))
}

/// Build a header with one more password slot. `existing_password` may be any
/// password of the file.
pub fn build_header_with_added_passphrase<R: Read + Seek>(
    file: &mut R,
    existing_password: &Secret<String>,
    new_password: &Secret<String>,
) -> Result<(Vec<u8>, usize), CoreErr> {
    let (mut opened, _, _, old_size) = open_for_edit(file, existing_password)?;
    let header = &mut opened.header;
    if header.password_slots.len() >= MAX_PASSWORD_SLOTS {
        return Err(CoreErr::EncryptFail(format!("Maximum number of passwords ({MAX_PASSWORD_SLOTS}) reached")));
    }
    let keys = new_password_keys(new_password, &header.public, &header.password_slots)?;
    header.password_slots.push(make_password_slot(opened.hdr_cipher, &keys, &opened.dek)?);
    Ok((seal_header(header, &opened.dek)?, old_size))
}

/// Build a header without the slot of `password_to_remove`.
///
/// `password` may be any password of the file, including the one being
/// removed — as long as the file keeps at least one key slot (password or
/// recipient).
pub fn build_header_with_removed_passphrase<R: Read + Seek>(
    file: &mut R,
    password: &Secret<String>,
    password_to_remove: &Secret<String>,
) -> Result<(Vec<u8>, usize), CoreErr> {
    let (mut opened, _, _, old_size) = open_for_edit(file, password)?;
    let header = &mut opened.header;
    let keys = derive_password_keys(password_to_remove.expose(), &header.public)?;
    let slot = header
        .password_slots
        .iter()
        .position(|s| slot_matches(&keys, s))
        .ok_or_else(|| CoreErr::DecryptFail("the password to remove does not open this file".into()))?;
    if header.key_slot_count() == 1 {
        return Err(CoreErr::DecryptFail(
            "cannot remove the last key slot — the file could never be opened again".into(),
        ));
    }
    header.password_slots.remove(slot);
    Ok((seal_header(header, &opened.dek)?, old_size))
}
