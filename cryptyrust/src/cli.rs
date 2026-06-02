use clap::{ArgGroup, Parser};
use arsenic::{ArsenicStrength, CipherId, KemLevel};
use std::path::PathBuf;

const ABOUT: &str = "
Arsenic file encryption — encrypts, decrypts, and manages keys.

Key management:
  cryptyrust keygen -n alice --store               Generate keypair (X25519 + ML-KEM-768)
  cryptyrust keygen -n alice --store --kem-level 1024  Generate keypair (ML-KEM-1024)
  cryptyrust keygen --list                         List stored keypairs

Encryption / decryption:
  cryptyrust -e FILE                               Encrypt (password, interactive prompt)
  cryptyrust -e FILE -R alice                      Encrypt for recipient (passwordless)
  cryptyrust -e FILE --kem-level 1024              Encrypt with ML-KEM-1024 keyslots
  cryptyrust -e FILE --armor                       Encrypt and ASCII-armor the output
  cryptyrust -e FILE --compress                    Encrypt with zstd compression (level 3)
  cryptyrust -e FILE --compress 9                  Encrypt with zstd compression level 9
  cryptyrust -d FILE                               Decrypt (auto-tries keystore, then password)
  cryptyrust -d FILE.armor                         Decrypt ASCII-armored file (auto-detected)
  cryptyrust --rekey FILE                          Change password
  cryptyrust --bench                               Benchmark ciphers

Recipient management:
  cryptyrust recipients list FILE                  List keyslots in a file
  cryptyrust recipients add FILE -R alice          Add a recipient keyslot
  cryptyrust recipients remove FILE -i KEY_FILE    Remove a recipient keyslot

Passphrase slot management:
  cryptyrust passphrase list FILE                  Count extra passphrase slots
  cryptyrust passphrase add FILE -p PW --new-pass NEW  Add a passphrase slot
  cryptyrust passphrase remove FILE -p PW --remove-pass OLD  Remove a passphrase slot

Author : Fabrice Corraire <antidote1911@gmail.com>
Github : https://github.com/Antidote1911/
";

#[derive(Parser)]
#[clap(about = ABOUT, author, version)]
#[clap(group(ArgGroup::new("mode").required(true).args(&["encrypt", "decrypt", "rekey", "bench"])))]
#[clap(group(ArgGroup::new("passwordflags").args(&["password", "passwordfile"])))]
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

    /// ML-KEM security level for recipient keyslots (encryption only).
    #[clap(long = "kem-level", value_enum, value_name = "LEVEL", default_value = "768")]
    kem_level: KemLevelArg,

    /// Wrap the encrypted output in ASCII armor (base64, BEGIN/END headers).
    ///
    /// On decrypt, armor is detected automatically — this flag is not needed.
    #[clap(long, short = 'a', action = clap::ArgAction::SetTrue)]
    armor: bool,

    /// Enable zstd compression before encryption (level 1–22, default 3).
    ///
    /// WARNING: compression leaks plaintext entropy via ciphertext size.
    /// Do not use for size-sensitive data.
    #[clap(long, value_name = "LEVEL", default_missing_value = "3",
           require_equals = false, num_args = 0..=1)]
    compress: Option<i32>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum StrengthArg { Interactive, Sensitive }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum KemLevelArg {
    #[clap(name = "768")]
    L768,
    #[clap(name = "1024")]
    L1024,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum CipherArg {
    /// Deoxys-II-256
    DeoxysIi,
    /// XChaCha20-Poly1305
    Xchacha20,
    /// AES-256-GCM-SIV
    AesGcmSiv,
}

// ── Key-management sub-command ────────────────────────────────────────────────

#[derive(Parser)]
#[clap(name = "cryptyrust keygen", author, version)]
#[clap(about = "Generate and manage hybrid keypairs (X25519 + ML-KEM-768)")]
pub struct KeygenCli {
    /// Name to embed in the key file.
    #[clap(short, long, value_name = "NAME", default_value = "")]
    pub name: String,

    /// Save the new keypair directly to the shared keystore
    /// (`{config}/cryptyrust/keys/`).  Requires --name.
    #[clap(short, long)]
    pub store: bool,

    /// Write the identity file to OUTPUT instead of stdout (permissions 0600 on Unix).
    #[clap(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// List all keypairs stored in the shared keystore and exit.
    #[clap(short, long)]
    pub list: bool,

    /// Convert identity file(s) to their public keys and print to stdout.
    /// Pass `-` to read from stdin.
    #[clap(short = 'y', long = "to-public", value_name = "IDENTITY", num_args = 1..)]
    pub to_public: Vec<String>,

    /// ML-KEM security level for new encryption keypairs.
    #[clap(long = "kem-level", value_enum, value_name = "LEVEL", default_value = "768")]
    pub kem_level: KemLevelArg,
}

// ── Passphrase slot management sub-command ────────────────────────────────────

#[derive(Parser)]
#[clap(name = "cryptyrust passphrase", author, version)]
#[clap(about = "Add, remove, or list extra passphrase keyslots in an .arsn file")]
pub struct PassphraseCli {
    #[clap(subcommand)]
    pub action: PassphraseAction,
}

#[derive(clap::Subcommand)]
pub enum PassphraseAction {
    /// Show the number of extra passphrase slots (primary slot not counted).
    List {
        #[clap(value_name = "FILE")]
        file: String,
    },

    /// Add an extra passphrase slot.
    ///
    /// After this, the file can be decrypted with either the primary password
    /// or the new password.
    ///
    /// NOTE: extra slots do not benefit from the HeaderMAC fast-fail — a wrong
    /// password pays the full Argon2id cost for each extra slot.
    Add {
        #[clap(value_name = "FILE")]
        file: String,

        /// Existing password to authenticate (primary slot recommended).
        #[clap(short, long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Read the existing password from a file.
        #[clap(short = 'f', long, value_name = "FILE")]
        passwordfile: Option<String>,

        /// New passphrase to add as an extra slot.
        #[clap(long = "new-pass", value_name = "PASSWORD")]
        new_pass: Option<String>,

        /// Read the new passphrase from a file.
        #[clap(long = "new-pass-file", value_name = "FILE")]
        new_pass_file: Option<String>,
    },

    /// Remove an extra passphrase slot.
    ///
    /// Requires the primary password to recompute the HeaderMAC.
    /// The primary slot itself cannot be removed.
    Remove {
        #[clap(value_name = "FILE")]
        file: String,

        /// Primary password (used for HeaderMAC authentication).
        #[clap(short, long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Read the primary password from a file.
        #[clap(short = 'f', long, value_name = "FILE")]
        passwordfile: Option<String>,

        /// The passphrase slot to remove.
        #[clap(long = "remove-pass", value_name = "PASSWORD")]
        remove_pass: Option<String>,

        /// Read the passphrase-to-remove from a file.
        #[clap(long = "remove-pass-file", value_name = "FILE")]
        remove_pass_file: Option<String>,
    },
}

// ── Recipient management sub-command ─────────────────────────────────────────

#[derive(Parser)]
#[clap(name = "cryptyrust recipients", author, version)]
#[clap(about = "List, add, or remove asymmetric keyslots from an .arsn file")]
pub struct RecipientsCli {
    #[clap(subcommand)]
    pub action: RecipientsAction,
}

#[derive(clap::Subcommand)]
pub enum RecipientsAction {
    /// List keyslots, matching them to known identities where possible.
    ///
    /// Probes the keystore and any supplied -i files to identify slot owners.
    /// No password is required.
    List {
        /// The .arsn file to inspect.
        #[clap(value_name = "FILE")]
        file: String,

        /// Extra identity file(s) to probe in addition to the shared keystore.
        #[clap(short = 'i', long = "identity", value_name = "KEY_FILE", action = clap::ArgAction::Append)]
        identities: Vec<String>,
    },

    /// Add a recipient keyslot to an existing file.
    Add {
        /// The .arsn file to modify.
        #[clap(value_name = "FILE")]
        file: String,

        /// Recipient to add (contact name stored in keystore, or path to a .key file).
        #[clap(short = 'R', long = "recipient", value_name = "SPEC")]
        recipient: String,

        /// Password (not recommended — appears in shell history).
        #[clap(short, long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Read the password from a UTF-8 file.
        #[clap(short = 'f', long, value_name = "FILE")]
        passwordfile: Option<String>,
    },

    /// Remove a recipient keyslot from an existing file.
    ///
    /// Specify the recipient either by identity file (-i) or by slot index (--slot).
    /// Use `cryptyrust recipients list FILE` to discover slot indices.
    ///
    /// The symmetric password is always required to authorize the operation and
    /// recompute the HeaderMAC. Files encrypted with recipients only (no password)
    /// cannot have keyslots removed post-hoc unless they were also given a password.
    Remove {
        /// The .arsn file to modify.
        #[clap(value_name = "FILE")]
        file: String,

        /// Remove the keyslot that matches this identity file.
        #[clap(short = 'i', long = "identity", value_name = "KEY_FILE")]
        identity: Option<String>,

        /// Remove the keyslot at this index (0-based).
        #[clap(long, value_name = "N")]
        slot: Option<usize>,

        /// Password (not recommended — appears in shell history).
        #[clap(short, long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Read the password from a UTF-8 file.
        #[clap(short = 'f', long, value_name = "FILE")]
        passwordfile: Option<String>,
    },
}

// ── Main CLI ──────────────────────────────────────────────────────────────────

impl Cli {
    pub fn password(&self)    -> Option<String> { self.password.clone() }
    pub fn passwordfile(&self) -> Option<&str>  { self.passwordfile.as_deref() }
    pub fn output(&self)       -> Option<&str>  { self.output.as_deref() }
    pub fn encrypt(&self)      -> Option<&str>  { self.encrypt.as_deref() }
    pub fn decrypt(&self)      -> Option<&str>  { self.decrypt.as_deref() }
    pub fn rekey(&self)        -> Option<&str>  { self.rekey.as_deref() }
    pub fn bench(&self)        -> bool          { self.bench }
    pub fn recipients(&self)   -> &[String]     { &self.recipients }
    pub fn identities(&self)   -> &[String]     { &self.identities }

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
    pub fn kem_level(&self) -> KemLevel {
        match self.kem_level {
            KemLevelArg::L768  => KemLevel::L768,
            KemLevelArg::L1024 => KemLevel::L1024,
        }
    }
    pub fn armor(&self)    -> bool          { self.armor }
    pub fn compress(&self) -> Option<i32>   { self.compress }
}
