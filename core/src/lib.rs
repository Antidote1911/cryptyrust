mod constants;
mod os_interface;
mod keygen;
use keygen::get_argon2_key;

pub use os_interface::*;
use std::time::Instant;
use serde::{Deserialize, Serialize};

use argon2::{password_hash::{rand_core::{OsRng, RngCore}, SaltString}};

use crypto_secretstream::*;
use std::io::prelude::*;
use std::{error, fmt};

const CHUNKSIZE: usize = 1024 * 512;
const SIGNATURE: [u8; 4] = [0xC1, 0x0A, 0x6B, 0xED];
const SALTBYTES: usize = 16;
const KEYBYTES: usize = 32;
const ABYTES: usize = 17;

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
    salt: [u8; SALTBYTES],
    streamheader: [u8; Header::BYTES],
}

pub fn encrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<(), Box<dyn error::Error>> {
    let mut total_bytes_read = 0;

    let mut salt_bytes = [0; SALTBYTES];
    OsRng.fill_bytes(&mut salt_bytes);
    let saltstring = SaltString::b64_encode(&salt_bytes).map_err(|e| e.to_string())?;
    let key = get_argon2_key(&password, &saltstring)?;
    let (header, mut stream) = PushStream::init(&mut rand_core::OsRng, &key);

    let headerfile = Headerfile {
        signature: SIGNATURE,
        salt: salt_bytes,
        streamheader: *header.as_ref()
    };
    let encoded: Vec<u8> = bincode::serialize(&headerfile)?;
    output.write_all(encoded.as_ref())?;
    //println!("{}",encoded.len());

    let mut eof = false;
    let start = Instant::now();
    while !eof {
        let res = read_up_to(input, CHUNKSIZE)?;
        eof = res.0;
        let mut buffer = res.1;
        total_bytes_read += buffer.len();
        let tag = if eof { Tag::Final } else { Tag::Message };
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
        stream.push(&mut buffer, &[], tag).map_err(|e| e.to_string())?;
        output.write_all(&buffer)?;
    }
    let duration = start.elapsed();
    let executiontime = duration.as_secs_f64().to_string();
    println!("{}",executiontime);

    Ok(())
}

pub fn decrypt<I: Read, O: Write>(
    input: &mut I,
    output: &mut O,
    password: &str,
    ui: &Box<dyn Ui>,
    filesize: Option<usize>,
) -> Result<(), Box<dyn error::Error>> {

    //deserialize input read from file
    let mut rawheader = [0u8; 44];
    input.read_exact(&mut rawheader)?;

    let decoded: Headerfile = bincode::deserialize(&rawheader).map_err(|e| e.to_string())?;
    let (signature, salt, streamheader) =
        (decoded.signature, decoded.salt, decoded.streamheader);

    match signature {
        SIGNATURE => println!("Good signature from Cryptyrust {}",constants::APP_VERSION),
        _=> return Err("Incorrect signature. Not a Cryptyrust encrypted file".to_string().into()),
    }

    let saltstring = SaltString::b64_encode(&salt).map_err(|e| e.to_string())?;

    let header = Header::try_from(streamheader.as_ref()).unwrap();

    let key = get_argon2_key(&password, &saltstring)?;
    let mut stream = PullStream::init(header, &key);

    let mut total_bytes_read = 0;
    let mut tag = Tag::Message;
    while tag != Tag::Final {
        let (_eof, mut buffer) = read_up_to(input, CHUNKSIZE + ABYTES)?;
        total_bytes_read += buffer.len();
        tag = match stream.pull(&mut buffer, &[]) {
            Ok(tag) => tag,
            Err(_) => return Err("Error: Incorrect password".to_string().into()),
        };
        if let Some(size) = filesize {
            let percentage = (((total_bytes_read as f32) / (size as f32)) * 100.) as i32;
            ui.output(percentage);
        }
        output.write_all(&buffer)?;
    }
    ui.output(100);
    Ok(())
}

// returns Ok(true, buffer) if EOF, and Ok(false, buffer) if buffer was filled without EOF
fn read_up_to<R: Read>(reader: &mut R, limit: usize) -> std::io::Result<(bool, Vec<u8>)> {
    let mut bytes_read = 0;
    let mut buffer = vec![0u8; limit];
    while bytes_read < limit {
        match reader.read(&mut buffer[bytes_read..]) {
            Ok(x) if x == 0 => {
                // EOF
                buffer.truncate(bytes_read);
                return Ok((true, buffer));
            }
            Ok(x) => bytes_read += x,
            Err(e) => return Err(e),
        };
    }
    buffer.truncate(bytes_read);
    Ok((false, buffer))
}

