//! Uniform encrypt/decrypt interface over the three supported AEAD ciphers.
//!
//! All ciphers produce a 16-byte authentication tag, so ciphertext lengths are
//! always `plaintext_len + 16` regardless of the algorithm chosen.
//!
//! Nonce conventions
//! -----------------
//! * **Envelope** functions: the header stores a 12-byte `kek_nonce`.  For
//!   AES-256-GCM-SIV that is used as-is (12-byte nonce).  For Deoxys-II-256
//!   it is BLAKE3-expanded to 15 bytes.  For XChaCha20-Poly1305 it is
//!   BLAKE3-expanded to 24 bytes.  The stored field size never changes.
//! * **Block** functions: the caller always supplies a 24-byte derived nonce.
//!   AES-256-GCM-SIV uses the first 12 bytes; Deoxys-II-256 uses the first
//!   15 bytes; XChaCha20-Poly1305 uses all 24.

use aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as AesGcmSivNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use deoxys::DeoxysII256;

use crate::errors::CoreErr;

use super::CipherId;

/// BLAKE3-expand a 12-byte nonce to 24 bytes for XChaCha20 header use.
fn expand_12_to_24(n: &[u8; 12]) -> [u8; 24] {
    blake3::derive_key("Arsenic V1 KEK Nonce XChaCha20", n.as_slice())[..24]
        .try_into().expect("24 <= 32")
}

/// BLAKE3-expand a 12-byte nonce to 15 bytes for Deoxys-II-256 header use.
fn expand_12_to_15(n: &[u8; 12]) -> [u8; 15] {
    blake3::derive_key("Arsenic V1 KEK Nonce DeoxysII256", n.as_slice())[..15]
        .try_into().expect("15 <= 32")
}

/// Encrypt the key envelope using the chosen header cipher.
///
/// `kek_nonce` is always the 12-byte field stored in the header.
pub(crate) fn envelope_encrypt(
    cipher_id: CipherId,
    key: &[u8; 32],
    kek_nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    match cipher_id {
        CipherId::DeoxysII256 => {
            let nonce15 = expand_12_to_15(kek_nonce);
            let cipher = DeoxysII256::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = Nonce::<DeoxysII256>::from_slice(&nonce15);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Envelope encryption failed".into()))
        }
        CipherId::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = AesGcmSivNonce::from_slice(kek_nonce);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Envelope encryption failed".into()))
        }
        CipherId::XChaCha20Poly1305 => {
            let nonce24 = expand_12_to_24(kek_nonce);
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = XNonce::from_slice(&nonce24);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Envelope encryption failed".into()))
        }
    }
}

/// Decrypt the key envelope using the chosen header cipher.
pub(crate) fn envelope_decrypt(
    cipher_id: CipherId,
    key: &[u8; 32],
    kek_nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    match cipher_id {
        CipherId::DeoxysII256 => {
            let nonce15 = expand_12_to_15(kek_nonce);
            let cipher = DeoxysII256::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = Nonce::<DeoxysII256>::from_slice(&nonce15);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
        CipherId::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = AesGcmSivNonce::from_slice(kek_nonce);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
        CipherId::XChaCha20Poly1305 => {
            let nonce24 = expand_12_to_24(kek_nonce);
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = XNonce::from_slice(&nonce24);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
    }
}

/// Encrypt a payload block.
///
/// `nonce24` is always 24 bytes (derived per-block via BLAKE3).
/// AES-256-GCM-SIV uses the first 12; Deoxys-II-256 uses the first 15;
/// XChaCha20-Poly1305 uses all 24.
pub(crate) fn block_encrypt(
    cipher_id: CipherId,
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    match cipher_id {
        CipherId::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = XNonce::from_slice(nonce24);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Block encryption failed".into()))
        }
        CipherId::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = AesGcmSivNonce::from_slice(&nonce24[..12]);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Block encryption failed".into()))
        }
        CipherId::DeoxysII256 => {
            let cipher = DeoxysII256::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = Nonce::<DeoxysII256>::from_slice(&nonce24[..15]);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CoreErr::EncryptFail("Block encryption failed".into()))
        }
    }
}

/// Decrypt a payload block.
pub(crate) fn block_decrypt(
    cipher_id: CipherId,
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    match cipher_id {
        CipherId::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = XNonce::from_slice(nonce24);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
        CipherId::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = AesGcmSivNonce::from_slice(&nonce24[..12]);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
        CipherId::DeoxysII256 => {
            let cipher = DeoxysII256::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
            let nonce = Nonce::<DeoxysII256>::from_slice(&nonce24[..15]);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CoreErr::DecryptionError)
        }
    }
}
