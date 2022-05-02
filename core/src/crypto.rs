use crate::errors::*;
use crate::keygen::*;
use crate::constants::*;
use crate::Ui;

use rand::{rngs::OsRng, Rng};
use aes_gcm_siv::{Aes256GcmSiv};
use aead::{stream, NewAead};
use zeroize::Zeroize;

use std::{
    io::{Read, Write}
};

pub fn encrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<(), CoreErr> {

    let mut total_bytes_read = 0;

    let mut salt: [u8; SALTLEN] = OsRng.gen();
    let mut nonce:[u8; NONCELEN] = OsRng.gen();

    let mut key = get_argon2_key(&password, &salt).expect("Argon derivation failed");

    let aead = Aes256GcmSiv::new(key[..KEYLEN].as_ref().into());
    let mut stream_encryptor=stream::EncryptorBE32::from_aead(aead, &nonce.into());

    output.write_all(&SIGNATURE)?;
    output.write_all(&salt)?;
    output.write_all(&nonce)?;

    let mut buffer = vec![0; MSGLEN + TAGLEN];
    let mut filled = 0;

    loop {
        // We leave space for the tag
        let read_count = input.read(&mut buffer[filled..MSGLEN])?;
        filled += read_count;
        total_bytes_read += buffer.len();

        if filled == MSGLEN {
            buffer.truncate(MSGLEN);
            stream_encryptor
                .encrypt_next_in_place(&[], &mut buffer)
                .map_err(|e| CoreErr::EncryptFail(e.to_string()))?;
            output.write_all(&buffer)?;
            filled = 0;
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_encryptor
                .encrypt_last_in_place(&[], &mut buffer)
                .map_err(|e| CoreErr::EncryptFail(e.to_string()))?;
            output.write_all(&buffer).map_err(|e| CoreErr::EncryptFail(e.to_string()))?;
            break;
        }
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    Ok(())
}

pub fn decrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<(), CoreErr> {

    let mut total_bytes_read = 0;

    let mut signature = [0u8; SIGNATURE.len()];
    let mut salt = [0u8; SALTLEN];
    let mut nonce = [0u8; NONCELEN];

    input.read_exact(&mut signature).map_err(|_| CoreErr::ReadSignature)?;
    input.read_exact(&mut salt).map_err(|_| CoreErr::ReadSalt)?;
    input.read_exact(&mut nonce).map_err(|_| CoreErr::ReadNonce)?;

    if signature != SIGNATURE{
        return Err(CoreErr::BadSignature);
    }

    let mut key = get_argon2_key(&password, &salt).expect("Argon derivation failed");
    let aead = Aes256GcmSiv::new(key[..KEYLEN].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, &nonce.into());

    let mut buffer = vec![0u8; MSGLEN + TAGLEN];
    let mut filled = 0;
    loop {
        // here we fill all the way to MSG_LEN + TAG_LEN, so we can omit the range end
        let read_count = input.read(&mut buffer[filled..])?;
        filled += read_count;
        total_bytes_read += buffer.len();

        if filled == MSGLEN + TAGLEN {
            stream_decryptor
                .decrypt_next_in_place(&[], &mut buffer)
                .map_err(|_| CoreErr::DecryptionError)?;

            output.write_all(&buffer)?;
            filled = 0;
            buffer.resize(MSGLEN + TAGLEN, 0);
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_decryptor
                .decrypt_last_in_place(&[], &mut buffer)
                .map_err(|_| CoreErr::DecryptionError)?;
            output.write_all(&buffer)?;
            break;
        }
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
    }
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    Ok(())
}
