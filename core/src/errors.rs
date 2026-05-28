use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreErr {
    #[error("Error: Unable to create cipher with argon2id hashed key.")]
    CreateCipher,

    #[error("Error: unable to initialising argon2id parameters")]
    Argon2Params,

    #[error("Error: unable to hash password with Argon2")]
    Argon2Hash,

    #[error("Decryption failed: Incorrect password or corrupted file.")]
    DecryptionError,

    #[error("Read error")]
    ReadError { source: std::io::Error },

    #[error("Read error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Decryption failed: {0}")]
    DecryptFail(String),

    #[error("{0} Can't delete: {1}")]
    DeleteFail(String, String),

    #[error("Encryption failed: {0}")]
    EncryptFail(String),

    #[error("Decryption failed: Incorrect signature. Not a valid Arsenic V1 file.")]
    BadSignature,

    #[error("Decryption failed: Incorrect header version.")]
    BadHeaderVersion,
}
