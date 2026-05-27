use crate::constants::*;
use crate::errors::*;
use crate::header::{create_aad, Header, HeaderType};
use crate::keygen::*;
use crate::secret::*;
use crate::{
    Algorithm, BenchMode, DecryptStreamCiphers, DeriveStrength, EncryptStreamCiphers, HashMode, Ui,
};
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aead::{KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use rand::random;
use std::io::{Read, Write};

pub fn init_encryption_stream(
    password: &Secret<String>,
    header_type: HeaderType,
) -> Result<(EncryptStreamCiphers, Header), CoreErr> {
    let salt = gen_salt();
    let key = argon2_hash(
        password,
        &salt,
        &header_type.header_version,
        &header_type.derive,
    )?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = random::<[u8; 8]>();
            let cipher =
                Aes256Gcm::new_from_slice(key.expose()).map_err(|_| CoreErr::CreateCipher)?;
            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((EncryptStreamCiphers::Aes256Gcm(Box::new(stream)), header))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = random::<[u8; 20]>();
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha20Poly1305(Box::new(stream)),
                header,
            ))
        }
        Algorithm::Aes256GcmSiv => {
            let nonce_bytes = random::<[u8; 8]>();
            let cipher =
                Aes256GcmSiv::new_from_slice(key.expose()).map_err(|_| CoreErr::CreateCipher)?;
            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((EncryptStreamCiphers::Aes256GcmSiv(Box::new(stream)), header))
        }
    }
}

pub fn init_decryption_stream(
    password: &Secret<String>,
    header: Header,
) -> Result<DecryptStreamCiphers, CoreErr> {
    let key = argon2_hash(
        password,
        &header.salt,
        &header.header_type.header_version,
        &header.header_type.derive,
    )?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key.expose()).map_err(|_| CoreErr::CreateCipher)?;
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha20Poly1305(Box::new(stream)))
        }
        Algorithm::Aes256GcmSiv => {
            let cipher =
                Aes256GcmSiv::new_from_slice(key.expose()).map_err(|_| CoreErr::CreateCipher)?;
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256GcmSiv(Box::new(stream)))
        }
    }
}

/// Reads exactly `buf.len()` bytes or until EOF, handling partial reads.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut nread = 0;
    while nread < buf.len() {
        match reader.read(&mut buf[nread..])? {
            0 => break,
            n => nread += n,
        }
    }
    Ok(nread)
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
    algorithm: Algorithm,
    derive: DeriveStrength,
    hash: HashMode,
    bench: BenchMode,
) -> Result<(), CoreErr> {
    let header_type = HeaderType {
        header_version: VERSION,
        algorithm,
        derive,
    };

    let (mut streams, header) = init_encryption_stream(password, header_type)?;

    if bench == BenchMode::WriteToFilesystem {
        crate::header::write_to_file(output, &header)?;
    }

    let mut hasher = blake3::Hasher::new();
    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, &header);
    }

    let aad = create_aad(&header);
    let mut buffer = vec![0u8; MSGLEN];
    let mut total_bytes_read = 0u64;

    loop {
        let read_count = read_full(input, &mut buffer)?;
        total_bytes_read += read_count as u64;
        if read_count == MSGLEN {
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let encrypted_data = streams
                .encrypt_next(payload)
                .map_err(|_| CoreErr::EncryptFail("Unable to encrypt the data".to_string()))?;
            if bench == BenchMode::WriteToFilesystem {
                output.write_all(&encrypted_data)?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&encrypted_data);
            }
            let percentage = ((total_bytes_read as f32 / filesize as f32) * 100.) as i32;
            ui.output(percentage);
        } else {
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };
            let encrypted_data = streams
                .encrypt_last(payload)
                .map_err(|_| CoreErr::EncryptFail("Unable to encrypt the data".to_string()))?;
            if bench == BenchMode::WriteToFilesystem {
                output.write_all(&encrypted_data)?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&encrypted_data);
            }
            ui.output(100);
            break;
        }
    }

    if bench == BenchMode::WriteToFilesystem {
        output.flush()?;
    }
    if hash == HashMode::CalculateHash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash Blake3 of the encrypted file is: {}", hash);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    password: &Secret<String>,
    ui: &dyn Ui,
    filesize: u64,
    hash: HashMode,
    bench: BenchMode,
) -> Result<(), CoreErr> {
    let mut hasher = blake3::Hasher::new();
    let (header, aad) = crate::header::read_from_file(input)?;

    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, &header);
    }

    let mut streams = init_decryption_stream(password, header)?;
    let mut buffer = vec![0u8; MSGLEN + TAGLEN];
    let mut total_bytes_read = 0u64;

    loop {
        let read_count = read_full(input, &mut buffer)?;
        total_bytes_read += read_count as u64;
        if read_count == (MSGLEN + TAGLEN) {
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let decrypted_data = streams
                .decrypt_next(payload)
                .map_err(|_| CoreErr::DecryptionError)?;
            if bench == BenchMode::WriteToFilesystem {
                output.write_all(&decrypted_data)?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer);
            }
            let percentage = ((total_bytes_read as f32 / filesize as f32) * 100.) as i32;
            ui.output(percentage);
        } else {
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };
            let decrypted_data = streams
                .decrypt_last(payload)
                .map_err(|_| CoreErr::DecryptionError)?;
            if bench == BenchMode::WriteToFilesystem {
                output.write_all(&decrypted_data)?;
                output.flush()?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer[..read_count]);
            }
            ui.output(100);
            break;
        }
    }

    if hash == HashMode::CalculateHash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash Blake3 of the encrypted file is: {}. If this doesn't match with the original, something very bad has happened.", hash);
    }
    Ok(())
}
