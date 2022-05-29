use crate::keygen::*;
use crate::constants::*;
use crate::{Algorithm, DecryptStreamCiphers, EncryptStreamCiphers, Ui};
use rand::{rngs::OsRng, Rng};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use aead::{NewAead};
use std::{io::{Read, Write}};
use aead::generic_array::GenericArray;
use aead::stream::{DecryptorBE32, EncryptorBE32};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

pub fn encrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
    algorithm: Algorithm,
) -> Result<()> {
    let bench=false;
    let (mut streams, salt, nonce_bytes): (EncryptStreamCiphers, [u8; SALTLEN], Vec<u8>) =
        match algorithm {
            Algorithm::AesGcm => {
                let salt: [u8; SALTLEN] = OsRng.gen();
                let nonce_bytes:[u8; NONCELEN] = OsRng.gen();
                let nonce = GenericArray::from_slice(&nonce_bytes);

                let key = get_argon2_key(&password, &salt ).expect("Argon derivation failed");

                let cipher = match Aes256GcmSiv::new_from_slice(&key) {
                    Ok(cipher) => {
                        drop(key);
                        cipher
                    }
                    Err(_) => {
                        return Err(anyhow!("Unable to create cipher with argon2id hashed key."))

                    }
                };

                let stream = EncryptorBE32::from_aead(cipher, &nonce);
                (
                    EncryptStreamCiphers::AesGcm(Box::new(stream)),
                    salt,
                    nonce.to_vec(),
                )
            }
            Algorithm::XChaCha20Poly1305 => {
                let salt: [u8; SALTLEN] = OsRng.gen();
                let nonce_bytes:[u8; XNONCELEN] = OsRng.gen();

                let key = get_argon2_key(&password,&salt).expect("Argon derivation failed");
                let cipher = match XChaCha20Poly1305::new_from_slice(&key) {
                    Ok(cipher) => {
                        drop(key);
                        cipher
                    }
                    Err(_) => {
                        return Err(anyhow!("Unable to create cipher with argon2id hashed key."))
                    }
                };

                let stream = EncryptorBE32::from_aead(cipher, nonce_bytes.as_slice().into());
                (
                    EncryptStreamCiphers::XChaCha(Box::new(stream)),
                    salt,
                    nonce_bytes.to_vec(),
                )
            }

        };

    if !bench {
        output.write_all(&SIGNATURE).context("Unable to write signature to the output file")?;
        output.write_all(&salt).context("Unable to write salt to the output file")?;

        match algorithm {
            Algorithm::XChaCha20Poly1305 => {
                output
                    .write_all("CHACHA".as_ref())
                    .context("Unable to write Ciphertype to the output file")?;
            }
            Algorithm::AesGcm => {
                output
                    .write_all("AESGCM".as_ref())
                    .context("Unable to write Ciphertype to the output file")?;
            }
        }
        output
            .write_all(&nonce_bytes)
            .context("Unable to write nonce to the output file")?;
    }

    let mut buffer = [0u8; MSGLEN];

    let mut total_bytes_read = 0;
    loop {
        let read_count = input
            .read(&mut buffer)
            .context("Unable to read from the input file")?;
        total_bytes_read += buffer.len();

        if read_count == MSGLEN {
            let encrypted_data = match streams.encrypt_next(buffer.as_slice()) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt data."))
            };

            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            }
        } else {
            // if we read something less than BLOCK_SIZE, and have hit the end of the file
            let encrypted_data = match streams.encrypt_last(&buffer[..read_count]) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt data."))
            };

            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            }
            break;
        }
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    if !bench {
        output.flush().context("Unable to flush the output file")?;
    }
    Ok(())
}


pub fn decrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<()> {
    let bench=false;
    let mut signature = [0u8; SIGNATURE.len()];
    input.read_exact(&mut signature).context("Unable to read signature from the file")?;
    if signature != SIGNATURE{
        return Err(anyhow!("Bad signature."))
    }

    let mut salt = [0u8; SALTLEN];
    input.read(&mut salt).context("Unable to read salt from the file")?;

    let mut cipher_type = [0u8; 6];
    input.read(&mut cipher_type).context("Unable to read cipher type from the file")?;

    let key = get_argon2_key(&password,&salt).expect("Argon derivation failed");

    let mut streams: DecryptStreamCiphers = match cipher_type.as_ref() {
        b"AESGCM" => {
            let cipher = match Aes256GcmSiv::new_from_slice(&key) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let mut nonce_bytes = [0u8; NONCELEN];
            input.read(&mut nonce_bytes).context("Unable to read nonce from the file")?;

            let nonce = GenericArray::from_slice(&nonce_bytes);

            let stream = DecryptorBE32::from_aead(cipher, nonce);

            DecryptStreamCiphers::AesGcm(Box::new(stream))
        }
        b"CHACHA" => {
            let cipher = match XChaCha20Poly1305::new_from_slice(&key) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let mut nonce_bytes = [0u8; XNONCELEN];
            input.read(&mut nonce_bytes).context("Unable to read nonce from the file")?;

            let stream = DecryptorBE32::from_aead(cipher, nonce_bytes.as_slice().into());
            DecryptStreamCiphers::XChaCha(Box::new(stream))
        }
        _ => unreachable!()
    };

    let mut buffer = [0u8; MSGLEN + TAGLEN]; // 16 bytes is the length of the AEAD tag
    let mut total_bytes_read = 0;
    loop {
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count;
        if read_count == (MSGLEN + TAGLEN) {
            let decrypted_data = match streams.decrypt_next(buffer.as_slice()) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file.")),
            };
            if !bench {
                output.write_all(&decrypted_data).context("Unable to write to the output file")?;
            }
        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            let decrypted_data = match streams.decrypt_last(&buffer[..read_count]) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the final block of data. Maybe it's the wrong key, or it's not an encrypted file.")),
            };

            if !bench {
                output.write_all(&decrypted_data).context("Unable to write to the output file")?;
                output.flush().context("Unable to flush the output file")?;
            }
            break;
        }
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    Ok(())
}

