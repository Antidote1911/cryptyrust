use thiserror::Error;

/// WordCountError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum CoreErr {
    /// Represents an empty source. For example, an empty text file being given
    /// as input to `count_words()`.
    #[error("Decryption failed: Incorect signature. Not a Cryptyrust encryped file.")]
    BadSignature,

    #[error("Decryption failed: Cant read signature.")]
    ReadSignature,

    #[error("Decryption failed: Cant read salt.")]
    ReadSalt,

    #[error("Decryption failed: Cant read nonce.")]
    ReadNonce,

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
}
