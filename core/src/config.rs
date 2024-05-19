use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Payload,
};
use aes_gcm::Aes256Gcm;
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use crate::secret::Secret;

#[derive(PartialEq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Copy, Clone)]
pub enum BenchMode {
    WriteToFilesystem,
    BenchmarkInMemory,
}

#[derive(Clone, Debug)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Copy, Clone)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    Aes256GcmSiv
}

#[derive(Copy, Clone)]
pub enum DeriveStrength {
    Interactive,
    Moderate,
    Sensitive,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            Algorithm::Aes256GcmSiv => write!(f, "Aes256-Gcm-Siv"),
        }
    }
}

pub struct Config {
    pub direction: Direction,
    pub algorithm: Algorithm,
    pub derivestrength:DeriveStrength,
    pub password: Secret<String>,
    pub filename: Option<String>,
    pub out_file: Option<String>,
    pub ui: Box<dyn Ui>,
    pub hashmode:HashMode,
    pub benchmode:BenchMode,
}

pub enum EncryptStreamCiphers {
    Aes256Gcm(Box<EncryptorLE31<Aes256Gcm>>),
    XChaCha(Box<EncryptorLE31<XChaCha20Poly1305>>),
    Aes256GcmSiv(Box<EncryptorLE31<Aes256GcmSiv>>),
}

pub enum DecryptStreamCiphers {
    Aes256Gcm(Box<DecryptorLE31<Aes256Gcm>>),
    XChaCha(Box<DecryptorLE31<XChaCha20Poly1305>>),
    Aes256GcmSiv(Box<DecryptorLE31<Aes256GcmSiv>>),
}

impl EncryptStreamCiphers {
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::Aes256Gcm(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::Aes256GcmSiv(s) => s.encrypt_next(payload),
        }
    }

    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::Aes256Gcm(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::Aes256GcmSiv(s) => s.encrypt_last(payload),
        }
    }
}

impl DecryptStreamCiphers {
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::Aes256Gcm(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::Aes256GcmSiv(s) => s.decrypt_next(payload),
        }
    }

    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::Aes256Gcm(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::Aes256GcmSiv(s) => s.decrypt_last(payload),
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
        derivestrength:DeriveStrength,
        password: Secret<String>,
        filename: Option<String>,
        out_file: Option<String>,
        ui: Box<dyn Ui>,
        hashmode:HashMode,
        benchmode:BenchMode,
    ) -> Self {
        let direction: Direction = _direction.clone();
        Config {
            direction,
            algorithm,
            derivestrength,
            password,
            filename,
            out_file,
            ui,
            hashmode,
            benchmode,
        }
    }
}