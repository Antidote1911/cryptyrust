// Manual Serpent-256-GCM implementation
// Follows NIST SP 800-38D (GCM specification)
// Serpent has 128-bit blocks and 256-bit key, compatible with GCM.

use cipher::{Block, BlockCipherEncrypt, KeyInit};
use serpent::Serpent as SerpentCipher;

use crate::errors::CoreErr;

pub(crate) struct SerpentGcm {
    cipher: SerpentCipher,
}

impl SerpentGcm {
    pub fn new(key: &[u8; 32]) -> Result<Self, CoreErr> {
        let cipher =
            SerpentCipher::new_from_slice(key).map_err(|_| CoreErr::CreateCipher)?;
        Ok(Self { cipher })
    }

    /// Encrypt a 16-byte block with Serpent.
    fn encrypt_raw(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut block = Block::<SerpentCipher>::default();
        block.as_mut_slice().copy_from_slice(input);
        self.cipher.encrypt_block(&mut block);
        let mut output = [0u8; 16];
        output.copy_from_slice(block.as_slice());
        output
    }

    /// GCM encrypt: returns ciphertext || 16-byte tag.
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let h = self.encrypt_raw(&[0u8; 16]);

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let ej0 = self.encrypt_raw(&j0);

        let ciphertext = self.ctr_encrypt(nonce, plaintext, 2);
        let s = ghash(h, aad, &ciphertext);

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = ej0[i] ^ s[i];
        }

        let mut out = ciphertext;
        out.extend_from_slice(&tag);
        out
    }

    /// GCM decrypt: expects ciphertext || 16-byte tag, returns plaintext.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, CoreErr> {
        if ciphertext_with_tag.len() < 16 {
            return Err(CoreErr::DecryptionError);
        }
        let (ct, tag_bytes) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let tag: [u8; 16] =
            tag_bytes.try_into().map_err(|_| CoreErr::DecryptionError)?;

        let h = self.encrypt_raw(&[0u8; 16]);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let ej0 = self.encrypt_raw(&j0);

        let expected_s = ghash(h, aad, ct);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = ej0[i] ^ expected_s[i];
        }

        // Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= expected_tag[i] ^ tag[i];
        }
        if diff != 0 {
            return Err(CoreErr::DecryptionError);
        }

        Ok(self.ctr_encrypt(nonce, ct, 2))
    }

    /// GCTR with big-endian 32-bit counter in the last 4 bytes of the block.
    fn ctr_encrypt(&self, nonce: &[u8; 12], data: &[u8], start_counter: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter = start_counter;
        for chunk in data.chunks(16) {
            let mut ctr_block = [0u8; 16];
            ctr_block[..12].copy_from_slice(nonce);
            ctr_block[12..16].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            let ks = self.encrypt_raw(&ctr_block);
            for (k, d) in ks[..chunk.len()].iter().zip(chunk) {
                out.push(k ^ d);
            }
        }
        out
    }
}

/// GF(2^128) multiplication — NIST SP 800-38D Appendix B.
/// Convention: MSB of byte 0 = coefficient of x^0.
fn gcm_mult(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = y;
    for xi in &x {
        for bit in (0..8).rev() {
            if (xi >> bit) & 1 == 1 {
                for k in 0..16 {
                    z[k] ^= v[k];
                }
            }
            let reduce = (v[15] & 1) == 1;
            // Right-shift v by 1 bit across all 16 bytes
            for k in (1..16).rev() {
                v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
            }
            v[0] >>= 1;
            if reduce {
                // XOR with R = 0xE1 00 ... 00 (x^7+x^2+x+1 in GCM bit order)
                v[0] ^= 0xE1;
            }
        }
    }
    z
}

/// GHASH_H(AAD || 0^pad || Ciphertext || 0^pad || len_A_bits || len_C_bits)
fn ghash(h: [u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for k in 0..16 {
            y[k] ^= block[k];
        }
        y = gcm_mult(y, h);
    }

    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for k in 0..16 {
            y[k] ^= block[k];
        }
        y = gcm_mult(y, h);
    }

    // Length block: [len(aad) in bits, 64-bit BE] || [len(ct) in bits, 64-bit BE]
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    for k in 0..16 {
        y[k] ^= len_block[k];
    }
    y = gcm_mult(y, h);

    y
}
