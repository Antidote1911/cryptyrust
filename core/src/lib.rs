mod constants;
mod keygen;
mod os_interface;
use keygen::key_derive_from_pass;

pub use os_interface::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use sodiumoxide::crypto::secretstream::xchacha20poly1305::{Header, Stream, Tag, ABYTES};

use sodiumoxide::crypto::pwhash::argon2id13::Salt;
use std::fs::File;
use std::io::prelude::*;
use std::{error, fmt};

const CHUNKSIZE: usize = 1024 * 512;
const SIGNATURE: [u8; 4] = [0xC1, 0x0A, 0x6B, 0xED];

#[derive(Debug)]
pub struct CoreError {
    message: String,
}

impl CoreError {
    fn _new(msg: &str) -> Self {
        CoreError {
            message: msg.to_string(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self.message)
    }
}

impl error::Error for CoreError {}

pub const fn get_version() -> &'static str {
    constants::APP_VERSION
}

//Struct to store a file signature, the salt for password hashing (Argon2),
// and the stream header (initial nonce)
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Headerfile {
    signature: [u8; 4],
    salt: Salt,
    streamheader: Header,
}

pub fn encrypt(
    input: &String,
    output: &String,
    password: &str,
    ui: &Box<dyn Ui>,
) -> Result<(), Box<dyn error::Error>> {
    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;
    let file_len = infile.metadata().unwrap().len();

    let (saltstring, key) = key_derive_from_pass(password, None);

    let (mut stream, header) = Stream::init_push(&key).unwrap();

    let headerfile = Headerfile {
        signature: SIGNATURE,
        salt: saltstring,
        streamheader: header,
    };

    let encoded: Vec<u8> = bincode::serialize(&headerfile)?;
    println!("{}", encoded.len());
    outfile.write_all(encoded.as_ref())?;
    let start = Instant::now();

    // encrypt
    let mut in_buff = [0u8; CHUNKSIZE];
    let mut out_buff: Vec<u8> = Vec::new();
    let num_iterations = f64::ceil(file_len as f64 / CHUNKSIZE as f64) as usize;
    for i in 0..num_iterations {
        let read_bytes = infile.read(&mut in_buff)?;
        let tag = if i == num_iterations - 1 {
            Tag::Final
        } else {
            Tag::Message
        };
        stream
            .push_to_vec(&in_buff[0..read_bytes], None, tag, &mut out_buff)
            .expect("Unable to push message stream");
        outfile.write_all(&out_buff[..])?;
    }

    //

    let duration = start.elapsed();
    let executiontime = duration.as_secs_f64().to_string();
    println!("{}", executiontime);

    Ok(())
}

pub fn decrypt(
    input: &String,
    output: &String,
    password: &str,
    ui: &Box<dyn Ui>,
) -> Result<(), Box<dyn error::Error>> {
    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;

    //deserialize input read from file
    let mut rawheader = [0u8; 60];
    infile.read_exact(&mut rawheader)?;

    let decoded: Headerfile = bincode::deserialize(&rawheader).map_err(|e| e.to_string())?;
    let (signature, salt, streamheader) = (decoded.signature, decoded.salt, decoded.streamheader);

    match signature {
        SIGNATURE => println!("Good signature from Cryptyrust {}", constants::APP_VERSION),
        _ => {
            return Err("Incorrect signature. Not a Cryptyrust encrypted file"
                .to_string()
                .into())
        }
    }

    let (_, key) = key_derive_from_pass(password, Some(salt));

    let mut stream =
        Stream::init_pull(&streamheader, &key).expect("Unable to initialize decryption stream");
    let mut in_buff = [0u8; CHUNKSIZE + ABYTES];
    let mut out_buff: Vec<u8> = Vec::new();
    //decrypt
    while stream.is_not_finalized() {
        let read_bytes = infile.read(&mut in_buff)?;
        match stream.pull_to_vec(&in_buff[0..read_bytes], None, &mut out_buff) {
            Ok(_) => (),
            Err(_) => return Err("Error: Incorrect password".to_string().into()),
        };
        outfile.write_all(&out_buff[..])?;
    }

    Ok(())
}
