use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use aead::{
    stream::{DecryptorBE32, EncryptorBE32},
    Payload, Result,
};


#[derive(Clone, Debug)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Copy, Clone)]
pub enum Algorithm {
    AesGcm,
    XChaCha20Poly1305,
}
impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::AesGcm => write!(f, "AESGCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "CHACHA"),
        }
    }
}

pub struct Config {
    pub direction: Direction,
    pub algorithm: Algorithm,
    pub password: String,
    pub filename: Option<String>,
    pub out_file: Option<String>,
    pub ui: Box<dyn Ui>,
}

pub enum EncryptStreamCiphers {
    AesGcm(Box<EncryptorBE32<Aes256GcmSiv>>),
    XChaCha(Box<EncryptorBE32<XChaCha20Poly1305>>),
}

pub enum DecryptStreamCiphers {
    AesGcm(Box<DecryptorBE32<Aes256GcmSiv>>),
    XChaCha(Box<DecryptorBE32<XChaCha20Poly1305>>),
}

impl EncryptStreamCiphers {
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_next(payload),
        }
    }

    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_last(payload),
        }
    }
}

impl DecryptStreamCiphers {
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_next(payload),
        }
    }

    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_last(payload),
        }
    }
}


pub trait Ui {
    fn output(&self, percentage: i32);
}

impl Config {
    pub fn new(
        _direction: Direction,
        algorithm: Algorithm,
        password: String,
        filename: Option<String>,
        out_file: Option<String>,
        ui: Box<dyn Ui>,
    ) -> Self {
        let direction: Direction = _direction.clone();
        Config {
            direction,
            algorithm,
            password,
            filename,
            out_file,
            ui,
        }
    }
}