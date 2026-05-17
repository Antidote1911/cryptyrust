use thiserror::Error;

/// WordCountError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum CoreErr {

    #[error("Decryption failed: Cant read signature.")]
    ReadSignature,

    #[error("Decryption failed: Cant read salt.")]
    ReadSalt,

    #[error("Decryption failed: Cant read nonce.")]
    ReadNonce,

    #[error("Error: Unable to create cipher with argon2id hashed key.")]
    CreateCipher,

    #[error("Error: unable to initialising argon2id parameters")]
    Argon2Params,

    #[error("Error: unable to hash password with Argon2")]
    Argon2Hash,

    /// Represents a failure in decryption routine
    #[error("Decryption failed: Incorrect password or corrupted file.")]
    DecryptionError,

    /// Represents a failure to read from input.
    #[error("Read error")]
    ReadError { source: std::io::Error },

    /// Represents all other cases of `std::io::Error`.
    #[error("Read error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Decryption failed: {0}")]
    DecryptFail(String),

    #[error("{0} Can't delete: {1}")]
    DeleteFail(String, String),

    #[error("Encryption failed: {0}")]
    EncryptFail(String),

    //// Header errors

    #[error("Decryption failed: Incorrect signature. Not a Cryptyrust encrypted file.")]
    BadSignature,

    #[error("Decryption failed: Incorrect header version.")]
    BadHeaderVersion,
}
