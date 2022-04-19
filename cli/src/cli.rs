use clap::{AppSettings, ArgGroup, Parser};

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

    /// Optional, and not recommended due to the password appearing in shell history. Password for the file. This or the --password-file (-f) flag is required if using stdin and/or stdout.
    #[clap(short, long, value_name = "PASSWORD")]
    password: Option<String>,

    /// The password to encrypt/decrypt with will be read from a text file at the path provided. File should be valid UTF-8 and contain only the password with no newline. This or the --password (-p) flag is required if using stdin and/or stdout.
    #[clap(short = 'f', long, value_name = "PASSWORD_FILE")]
    passwordfile: Option<String>,
}

impl Cli {}
