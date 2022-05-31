use crate::keygen::*;
use crate::constants::*;
use crate::errors::*;
use crate::{Algorithm, DecryptStreamCiphers, EncryptStreamCiphers, Ui};
use crate::header::{Header, HeaderType};
use crate::secret::*;
use rand::{Rng, SeedableRng};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::XChaCha20Poly1305;
use aead::{NewAead};
use std::{io::{Read, Write}};
use std::fs::File;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use deoxys::DeoxysII256;
use rand::prelude::StdRng;
use indicatif::{ProgressBar, ProgressStyle};

pub fn init_encryption_stream(
    password: &Secret<String>,
    header_type: &HeaderType,
) -> Result<(EncryptStreamCiphers, [u8; SALTLEN], Vec<u8>), CoreErr> {
    let salt = gen_salt();
    let key = argon2_hash(password, &salt, &header_type.header_version)?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();
            let nonce = Nonce::from_slice(&nonce_bytes);

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce);
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
    }
}

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for decrypt/stream mode and is the central place for managing streams for decryption
pub fn init_decryption_stream(
    password: &Secret<String>,
    header: Header,
) -> Result<DecryptStreamCiphers, CoreErr> {
    let key = argon2_hash(password, &header.salt, &header.header_type.header_version)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let nonce = Nonce::from_slice(header.nonce.as_slice());

            let stream = DecryptorLE31::from_aead(cipher, nonce);

            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
    }
}

pub fn encrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
    algorithm: Algorithm,
) -> Result<(), CoreErr> {

    let header_type = HeaderType {
        header_version: VERSION,
        algorithm,
    };

    let (mut streams, salt, nonce_bytes) = init_encryption_stream(password, &header_type)?;
    let header = Header {
        salt,
        nonce: nonce_bytes,
        header_type,
    };
    crate::header::write_to_file(output, &header)?;

    let mut buffer = [0u8; MSGLEN];
    let mut total_bytes_read = 0;
    let pb = ProgressBar::new(filesize.unwrap() as u64);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .with_key("eta", |state| format!("{:.1}s", state.eta().as_secs_f64()))
        .progress_chars("#>-"));
    loop {
        let read_count = input.read(&mut buffer).map_err(|e| CoreErr::IOError(e))?;
        total_bytes_read += read_count;
        if read_count == MSGLEN {
            let encrypted_data = match streams.encrypt_next(buffer.as_slice()) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::EncryptFail("Unable to encrypt the data".to_string()))
            };
                output
                    .write_all(&encrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
        } else {
            // if we read something less than BLOCK_SIZE, and have hit the end of the file
            let encrypted_data = match streams.encrypt_last(&buffer[..read_count]) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::EncryptFail("Unable to encrypt the data".to_string()))
            };
                output
                    .write_all(&encrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
            break;
        }
        pb.set_position(total_bytes_read as u64);
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    output.flush().map_err(|e| CoreErr::IOError(e))?;
    pb.finish();
    Ok(())
}


pub fn decrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<(), CoreErr> {

    let header=crate::header::read_from_file(input)?;
    let mut streams = init_decryption_stream(password, header)?;
    let mut buffer = [0u8; MSGLEN + 16]; // 16 bytes is the length of the AEAD tag

    let mut total_bytes_read = 0;
    let pb = ProgressBar::new(filesize.unwrap() as u64);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .with_key("eta", |state| format!("{:.1}s", state.eta().as_secs_f64()))
        .progress_chars("#>-"));
    loop {
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count;
        if read_count == (MSGLEN + 16) {
            let decrypted_data = match streams.decrypt_next(buffer.as_slice()) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::DecryptionError)
            };
                output
                    .write_all(&decrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            let decrypted_data = match streams.decrypt_last(&buffer[..read_count]) {
                Ok(bytes) => bytes,
                //Err(_) => return Err(anyhow!("Unable to decrypt the final block of data. Maybe it's the wrong key, or it's not an encrypted file.")),
                Err(_) => return Err(CoreErr::DecryptionError)
            };
                output.write_all(&decrypted_data).map_err(|e| CoreErr::IOError(e))?;
                output.flush().map_err(|e| CoreErr::IOError(e))?;
            break;
        }
        pb.set_position(total_bytes_read as u64);
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    pb.finish();
    Ok(())
}

