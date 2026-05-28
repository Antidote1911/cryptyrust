use clap::{ArgGroup, Parser};
use cryptyrust_core::{ArsenicStrength, CipherId};

const ABOUT: &str = "
A simple but strong file encryption utility in Rust.
Author : Fabrice Corraire <antidote1911@gmail.com>
Github : https://github.com/Antidote1911/
";

#[derive(Parser)]
#[clap(about=ABOUT, author, version)]
#[clap(group(ArgGroup::new("mode").required(true)
.args(&["encrypt", "decrypt", "rekey"]),
))]
#[clap(group(ArgGroup::new("passwordflags")
.args(&["password", "passwordfile"]),
))]
pub struct Cli {
    /// Specifies the file to encrypt.
    #[clap(long, short, value_name = "FILE_TO_ENCRYPT")]
    encrypt: Option<String>,

    /// Specifies the file to decrypt.
    #[clap(long, short, value_name = "FILE_TO_DECRYPT")]
    decrypt: Option<String>,

    /// Change the password of an encrypted .arsn file in-place.
    #[clap(long, short = 'k', value_name = "FILE_TO_REKEY")]
    rekey: Option<String>,

    /// Specifies the output file. Ignored in rekey mode.
    #[clap(long, short, value_name = "PATH_TO_OUTPUT_FILE")]
    output: Option<String>,

    /// Not recommended due to the password appearing in shell history. Ignored in rekey mode.
    #[clap(short, long, value_name = "PASSWORD")]
    password: Option<String>,

    /// File should be valid UTF-8 and contain only the password with no newline. Ignored in rekey mode.
    #[clap(short = 'f', long, value_name = "PASSWORD_FILE")]
    passwordfile: Option<String>,

    /// Argon2id strength preset. Ignored during decryption and rekey.
    #[clap(
        long,
        value_enum,
        value_name = "STRENGTH",
        default_value = "interactive"
    )]
    strength: StrengthArg,

    /// Cipher for the key envelope in the header (encryption only).
    #[clap(
        long = "hdr-cipher",
        value_enum,
        value_name = "CIPHER",
        default_value = "serpent-gcm"
    )]
    hdr_cipher: CipherArg,

    /// Cipher for each payload block (encryption only).
    #[clap(
        long = "pld-cipher",
        value_enum,
        value_name = "CIPHER",
        default_value = "xchacha20"
    )]
    pld_cipher: CipherArg,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum StrengthArg {
    Interactive,
    Sensitive,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum CipherArg {
    /// Serpent-256-GCM
    SerpentGcm,
    /// XChaCha20-Poly1305
    Xchacha20,
    /// AES-256-GCM-SIV
    AesGcmSiv,
}

impl Cli {
    pub fn password(&self) -> Option<String> {
        self.password.clone()
    }
    pub fn passwordfile(&self) -> Option<&str> {
        self.passwordfile.as_deref()
    }
    pub fn output(&self) -> Option<&str> {
        self.output.as_deref()
    }
    pub fn encrypt(&self) -> Option<&str> {
        self.encrypt.as_deref()
    }
    pub fn decrypt(&self) -> Option<&str> {
        self.decrypt.as_deref()
    }
    pub fn rekey(&self) -> Option<&str> {
        self.rekey.as_deref()
    }

    pub fn strength(&self) -> ArsenicStrength {
        match self.strength {
            StrengthArg::Interactive => ArsenicStrength::Interactive,
            StrengthArg::Sensitive => ArsenicStrength::Sensitive,
        }
    }

    pub fn hdr_cipher(&self) -> CipherId {
        match self.hdr_cipher {
            CipherArg::SerpentGcm => CipherId::SerpentGcm,
            CipherArg::Xchacha20 => CipherId::XChaCha20Poly1305,
            CipherArg::AesGcmSiv => CipherId::Aes256GcmSiv,
        }
    }

    pub fn pld_cipher(&self) -> CipherId {
        match self.pld_cipher {
            CipherArg::SerpentGcm => CipherId::SerpentGcm,
            CipherArg::Xchacha20 => CipherId::XChaCha20Poly1305,
            CipherArg::AesGcmSiv => CipherId::Aes256GcmSiv,
        }
    }
}
