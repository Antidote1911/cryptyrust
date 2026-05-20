use crate::keygen::*;
use crate::constants::*;
use crate::errors::*;
use crate::{Algorithm, BenchMode, DecryptStreamCiphers, DeriveStrength, EncryptStreamCiphers, HashMode, Ui};
use crate::header::{create_aad, Header, HeaderType};
use crate::secret::*;
use rand::{Rng, SeedableRng};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use aead::{Payload, KeyInit};
use std::io::{Read, Write};
use std::fs::File;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aes_gcm_siv::Aes256GcmSiv;
use rand::prelude::StdRng;


pub fn init_encryption_stream(
    password: &Secret<String>,
    header_type: HeaderType,
) -> Result<(EncryptStreamCiphers, Header), CoreErr> {
    let salt = gen_salt();
    let key = argon2_hash(password, &salt, &header_type.header_version, &header_type.derive)?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_os_rng().random::<[u8; 8]>();
            let cipher = Aes256Gcm::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let header = Header { header_type, nonce: nonce_bytes.to_vec(), salt };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((EncryptStreamCiphers::Aes256Gcm(Box::new(stream)), header))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_os_rng().random::<[u8; 20]>();
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let header = Header { header_type, nonce: nonce_bytes.to_vec(), salt };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((EncryptStreamCiphers::XChaCha20Poly1305(Box::new(stream)), header))
        }
        Algorithm::Aes256GcmSiv => {
            let nonce_bytes = StdRng::from_os_rng().random::<[u8; 8]>();
            let cipher = Aes256GcmSiv::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let header = Header { header_type, nonce: nonce_bytes.to_vec(), salt };
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((EncryptStreamCiphers::Aes256GcmSiv(Box::new(stream)), header))
        }
    }
}

pub fn init_decryption_stream(
    password: &Secret<String>,
    header: Header,
) -> Result<DecryptStreamCiphers, CoreErr> {
    let key = argon2_hash(password, &header.salt, &header.header_type.header_version, &header.header_type.derive)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
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
            let cipher = Aes256GcmSiv::new_from_slice(key.expose())
                .map_err(|_| CoreErr::CreateCipher)?;
            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256GcmSiv(Box::new(stream)))
        }
    }
}

pub fn encrypt(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
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
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count as u64;
        if read_count == MSGLEN {
            let payload = Payload { aad: &aad, msg: buffer.as_ref() };
            let encrypted_data = streams.encrypt_next(payload)
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
            let payload = Payload { aad: &aad, msg: &buffer[..read_count] };
            let encrypted_data = streams.encrypt_last(payload)
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

pub fn decrypt(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
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
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count as u64;
        if read_count == (MSGLEN + TAGLEN) {
            let payload = Payload { aad: &aad, msg: buffer.as_ref() };
            let decrypted_data = streams.decrypt_next(payload)
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
            let payload = Payload { aad: &aad, msg: &buffer[..read_count] };
            let decrypted_data = streams.decrypt_last(payload)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempfile;
    use std::io::{Write, Read, Seek};

    fn setup_temp_files() -> (File, File) {
        let mut input_file = tempfile().expect("Failed to create temp input file");
        let output_file = tempfile().expect("Failed to create temp output file");

        writeln!(input_file, "Données de test pour l'encryptage.")
            .expect("Failed to write to temp file");
        input_file.rewind().expect("Failed to rewind input file");

        (input_file, output_file)
    }

    #[test]
    fn test_encrypt() {
        let (mut input_file, mut output_file) = setup_temp_files();
        let password = Secret::new(String::from("mot_de_passe_test"));
        let mock_ui: Box<dyn Ui> = Box::new(MockUi {});
        let filesize = input_file.metadata().unwrap().len();

        let result = encrypt(
            &mut input_file,
            &mut output_file,
            &password,
            &mock_ui,
            filesize,
            Algorithm::Aes256Gcm,
            DeriveStrength::Interactive,
            HashMode::CalculateHash,
            BenchMode::WriteToFilesystem,
        );

        assert!(
            result.is_ok(),
            "Encryption failed with error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let (mut input_file, mut encrypted_file) = setup_temp_files();
        let mut decrypted_file = tempfile().expect("Failed to create temp decrypted file");
        let password = Secret::new(String::from("mot_de_passe_test"));
        let mock_ui: Box<dyn Ui> = Box::new(MockUi {});
        let filesize = input_file.metadata().unwrap().len();

        let enc_result = encrypt(
            &mut input_file,
            &mut encrypted_file,
            &password,
            &mock_ui,
            filesize,
            Algorithm::Aes256Gcm,
            DeriveStrength::Interactive,
            HashMode::CalculateHash,
            BenchMode::WriteToFilesystem,
        );
        assert!(
            enc_result.is_ok(),
            "Encryption failed with error: {:?}",
            enc_result.err()
        );

        encrypted_file.rewind().unwrap();

        let dec_result = decrypt(
            &mut encrypted_file,
            &mut decrypted_file,
            &password,
            &mock_ui,
            filesize,
            HashMode::CalculateHash,
            BenchMode::WriteToFilesystem,
        );
        assert!(
            dec_result.is_ok(),
            "Decryption failed with error: {:?}",
            dec_result.err()
        );

        let mut original_data = String::new();
        input_file.rewind().unwrap();
        input_file.read_to_string(&mut original_data).unwrap();

        let mut decrypted_data = String::new();
        decrypted_file.rewind().unwrap();
        decrypted_file.read_to_string(&mut decrypted_data).unwrap();

        assert_eq!(original_data, decrypted_data, "Decrypted data does not match original");
    }

    struct MockUi;
    impl Ui for MockUi {
        fn output(&self, _percentage: i32) {}
    }
}
