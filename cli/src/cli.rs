use clap::{ArgGroup, Parser};
use arsenic::{ArsenicStrength, CipherId};

const ABOUT: &str = "
Arsenic file encryption — encrypts and decrypts files with AEAD ciphers and
an Argon2id-derived key.  Asymmetric (X25519) recipients are supported: use
`crypty-keygen --store` to create a keypair, then pass `-R name` to encrypt.

Author : Fabrice Corraire <antidote1911@gmail.com>
Github : https://github.com/Antidote1911/
";

#[derive(Parser)]
#[clap(about=ABOUT, author, version)]
#[clap(group(ArgGroup::new("mode").required(true).args(&["encrypt","decrypt","rekey","bench"])))]
#[clap(group(ArgGroup::new("passwordflags").args(&["password","passwordfile"])))]
pub struct Cli {
    /// File to encrypt.
    #[clap(long, short, value_name = "FILE")]
    encrypt: Option<String>,

    /// File to decrypt.
    #[clap(long, short, value_name = "FILE")]
    decrypt: Option<String>,

    /// Change the password of an .arsn file in-place.
    #[clap(long, short = 'k', value_name = "FILE")]
    rekey: Option<String>,

    /// Output file or directory. Ignored in rekey mode.
    #[clap(long, short, value_name = "PATH")]
    output: Option<String>,

    /// Password (not recommended — appears in shell history).
    #[clap(short, long, value_name = "PASSWORD")]
    password: Option<String>,

    /// Read the password from a UTF-8 file (no trailing newline).
    #[clap(short = 'f', long, value_name = "FILE")]
    passwordfile: Option<String>,

    /// Encrypt for a recipient (repeatable).
    /// Each value can be:
    ///   - a public key string (arsenic1...)
    ///   - a contact name stored in the keystore
    ///   - a path to an identity file (.key)
    #[clap(short = 'R', long = "recipient", value_name = "PUBKEY_OR_NAME", action = clap::ArgAction::Append)]
    recipients: Vec<String>,

    /// Identity file to try for decryption (repeatable).
    /// If omitted, all keypairs in the shared keystore are tried automatically.
    #[clap(short = 'i', long = "identity", value_name = "KEY_FILE", action = clap::ArgAction::Append)]
    identities: Vec<String>,

    /// Argon2id strength preset. Ignored during decryption and rekey.
    #[clap(long, value_enum, value_name = "STRENGTH", default_value = "interactive")]
    strength: StrengthArg,

    /// Benchmark AEAD cipher throughput on this machine.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    bench: bool,

    /// Header cipher (encryption only).
    #[clap(long = "hdr-cipher", value_enum, value_name = "CIPHER", default_value = "deoxys-ii")]
    hdr_cipher: CipherArg,

    /// Payload cipher (encryption only).
    #[clap(long = "pld-cipher", value_enum, value_name = "CIPHER", default_value = "xchacha20")]
    pld_cipher: CipherArg,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum StrengthArg { Interactive, Sensitive }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum CipherArg {
    /// Deoxys-II-256
    DeoxysIi,
    /// XChaCha20-Poly1305
    Xchacha20,
    /// AES-256-GCM-SIV
    AesGcmSiv,
}

impl Cli {
    pub fn password(&self)     -> Option<String> { self.password.clone() }
    pub fn passwordfile(&self)  -> Option<&str>   { self.passwordfile.as_deref() }
    pub fn output(&self)        -> Option<&str>   { self.output.as_deref() }
    pub fn encrypt(&self)       -> Option<&str>   { self.encrypt.as_deref() }
    pub fn decrypt(&self)       -> Option<&str>   { self.decrypt.as_deref() }
    pub fn rekey(&self)         -> Option<&str>   { self.rekey.as_deref() }
    pub fn bench(&self)         -> bool           { self.bench }
    pub fn recipients(&self)    -> &[String]      { &self.recipients }
    pub fn identities(&self)    -> &[String]      { &self.identities }

    pub fn strength(&self) -> ArsenicStrength {
        match self.strength {
            StrengthArg::Interactive => ArsenicStrength::Interactive,
            StrengthArg::Sensitive   => ArsenicStrength::Sensitive,
        }
    }
    pub fn hdr_cipher(&self) -> CipherId {
        match self.hdr_cipher {
            CipherArg::DeoxysIi  => CipherId::DeoxysII256,
            CipherArg::Xchacha20 => CipherId::XChaCha20Poly1305,
            CipherArg::AesGcmSiv => CipherId::Aes256GcmSiv,
        }
    }
    pub fn pld_cipher(&self) -> CipherId {
        match self.pld_cipher {
            CipherArg::DeoxysIi  => CipherId::DeoxysII256,
            CipherArg::Xchacha20 => CipherId::XChaCha20Poly1305,
            CipherArg::AesGcmSiv => CipherId::Aes256GcmSiv,
        }
    }
}
