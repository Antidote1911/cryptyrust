use clap::{AppSettings, ArgGroup, ArgEnum, Parser};

const AUTHOR: &str = "
Author : Fabrice Corraire <antidote1911@gmail.com>
Github : https://github.com/Antidote1911/
";

#[derive(Parser)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
#[clap(about, author=AUTHOR, version)]

#[clap(group(ArgGroup::new("mode").required(true)
.args(&["encrypt", "decrypt"]),
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

    /// Specifies the output file.
    #[clap(long, short, value_name = "PATH_TO_OUTPUT_FILE")]
    output: Option<String>,

    /// Not recommended due to the password appearing in shell history.
    #[clap(short, long, value_name = "PASSWORD")]
    password: Option<String>,

    /// Choose algorithm. Ignored in decryption mode
    #[clap(short, long, arg_enum,value_name = "ALGO", default_value = "aesgcm")]
    algo: Algo,

    /// Choose password derivation strength
    #[clap(short, long, arg_enum,value_name = "STRENGTH", default_value = "interactive")]
    strength: Strength,

    /// File should be valid UTF-8 and contain only the password with no newline.
    #[clap(short='f', long, value_name = "PASSWORD_FILE")]
    passwordfile: Option<String>,

    /// Optional, output hash
    #[clap(short, long)]
    hash: bool,

    /// Optional, bench mode
    #[clap(short, long)]
    bench: bool,

}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum Algo {
    Aesgcm,
    Chacha,
    Deoxys,
    Aesgcmsiv,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum Strength {
    Interactive,
    Moderate,
    Sensitive,
}

impl Cli {
    pub fn algo(&self) -> Algo {
        self.algo
    }
    pub fn strength(&self) -> Strength {
        self.strength
    }
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
    pub fn hash(&self) -> bool {
        self.hash
    }
    pub fn bench(&self) -> bool {
        self.bench
    }
}