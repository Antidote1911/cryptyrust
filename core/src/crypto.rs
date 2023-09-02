use crate::keygen::*;
use crate::constants::*;
use crate::errors::*;
use crate::{Algorithm, BenchMode, DecryptStreamCiphers, DeriveStrength, EncryptStreamCiphers, HashMode, Ui};
use crate::header::{create_aad, Header, HeaderType};
use crate::secret::*;
use rand::{Rng, SeedableRng};
use aes_gcm::{Aes256Gcm};
use chacha20poly1305::XChaCha20Poly1305;
use aead::{NewAead, Payload};
use std::{io::{Read, Write}};
use std::fs::File;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aes_gcm_siv::Aes256GcmSiv;
use deoxys::DeoxysII256;
use rand::prelude::StdRng;
use indicatif::{ProgressBar, ProgressStyle};


pub fn init_encryption_stream(
    password: &Secret<String>,
    header_type: HeaderType,
) -> Result<(EncryptStreamCiphers, Header), CoreErr> {
    let salt = gen_salt();
    let key = argon2_hash(password, &salt, &header_type.header_version, &header_type.derive)?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                header,
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                header,
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                header,
            ))
        }
        Algorithm::Aes256GcmSiv => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256GcmSiv::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256GcmSiv(Box::new(stream)),
                header,
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
    let key = argon2_hash(password, &header.salt, &header.header_type.header_version,&header.header_type.derive)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
        Algorithm::Aes256GcmSiv => {
            let cipher = match Aes256GcmSiv::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(CoreErr::CreateCipher)
            };
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256GcmSiv(Box::new(stream)))
        }
    }
}

pub fn encrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: u64,
    algorithm: Algorithm,
    derive:DeriveStrength,
    hash: HashMode,
    bench: BenchMode,
) -> Result<(), CoreErr> {

    let header_type = HeaderType {
        header_version: VERSION,
        algorithm,
        derive,
    };

    let (mut streams, header) = init_encryption_stream(password, header_type).unwrap();

    if bench == BenchMode::WriteToFilesystem {
        crate::header::write_to_file(output, &header)?;
    }

    let mut hasher = blake3::Hasher::new();

    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, &header);
    }

    let aad = create_aad(&header);

    let mut buffer = [0u8; MSGLEN];
    let mut total_bytes_read = 0;
    let pb = ProgressBar::new(filesize as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
            .unwrap()
            .progress_chars("#>-"),);
    loop {
        let read_count = input.read(&mut buffer).map_err(|e| CoreErr::IOError(e))?;
        total_bytes_read += read_count;
        if read_count == MSGLEN {
            // aad is just empty bytes normally
            // create_aad returns empty bytes if the header isn't V3+
            // this means we don't need to do anything special in regards to older versions
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let encrypted_data = match streams.encrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::EncryptFail("Unable to encrypt the data".to_string()))
            };
            if bench == BenchMode::WriteToFilesystem {
                output
                    .write_all(&encrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&encrypted_data);
            }

        } else {
            // if we read something less than MSGLEN, and have hit the end of the file
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };

            let encrypted_data = match streams.encrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::EncryptFail("Unable to encrypt the data".to_string()))
            };
            if bench == BenchMode::WriteToFilesystem {
                output
                    .write_all(&encrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&encrypted_data);
            }
            break;
        }
        pb.set_position(total_bytes_read as u64);
        let percentage = (((total_bytes_read as f32) / (filesize as f32)) * 100.) as i32;
        ui.output(percentage);

    }
    pb.finish();
    if bench == BenchMode::WriteToFilesystem {
        output.flush().map_err(|e| CoreErr::IOError(e))?;
    }
    if hash == HashMode::CalculateHash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash Blake3 of the encrypted file is: {}", hash,);
    }
    Ok(())
}

pub fn decrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: u64,
    hash: HashMode,
    bench: BenchMode,
) -> Result<(), CoreErr> {
    let mut hasher = blake3::Hasher::new();

    let (header, aad)=crate::header::read_from_file(input)?;

    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, &header);
    }

    let mut streams = init_decryption_stream(password, header)?;
    let mut buffer = [0u8; MSGLEN + TAGLEN]; // TAGLEN is the length of the AEAD tag

    let mut total_bytes_read = 0;
    let pb = ProgressBar::new(filesize as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
            .unwrap()
            .progress_chars("#>-"),
    );
    loop {
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count;
        if read_count == (MSGLEN + TAGLEN) {
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let decrypted_data = match streams.decrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::DecryptionError)
            };
            if bench == BenchMode::WriteToFilesystem {
                output
                    .write_all(&decrypted_data)
                    .map_err(|e| CoreErr::IOError(e))?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer);
            }
        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };
            let decrypted_data = match streams.decrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(CoreErr::DecryptionError)
            };
            if bench == BenchMode::WriteToFilesystem {
                output.write_all(&decrypted_data).map_err(|e| CoreErr::IOError(e))?;
                output.flush().map_err(|e| CoreErr::IOError(e))?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer[..read_count]);
            }
            break;
        }
        pb.set_position(total_bytes_read as u64);

            let percentage = (((total_bytes_read as f32) / (filesize as f32)) * 100.) as i32;
            ui.output(percentage);

    }
    pb.finish();
    if hash == HashMode::CalculateHash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash Blake3 of the encrypted file is: {}. If this doesn't match with the original, something very bad has happened.", hash);
    }

    Ok(())
}

