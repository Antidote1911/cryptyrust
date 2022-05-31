use std::fs::File;
use std::io::{Read, Write};
use crate::errors::*;
use crate::{Algorithm, SALTLEN, SIGNATURE};


pub enum HeaderVersion {
    V1,
}

// the information needed to easily serialize a header
pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub algorithm: Algorithm,
}

// the data used returned after reading/deserialising a header
pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: [u8; SALTLEN],
}

// this writes a header to a file
// it handles padding and serialising the specific information
// it ensures the buffer is left at 64 bytes, so other functions can write the data without further hassle
pub fn write_to_file(file: &mut File, header: &Header) -> Result<(), CoreErr> {
    let nonce_len = calc_nonce_len(&header.header_type);

    match &header.header_type.header_version {
        HeaderVersion::V1 => {
            let padding = vec![0u8; 20 - nonce_len];
            let (version_info, algorithm_info) = serialize(&header.header_type);

            file.write_all(&SIGNATURE)
                .map_err(|e| CoreErr::IOError(e))?; // 4
            file.write_all(&version_info)
                .map_err(|e| CoreErr::IOError(e))?; // 2
            file.write_all(&algorithm_info)
                .map_err(|e| CoreErr::IOError(e))?; // 2
            file.write_all(&header.salt)
                .map_err(|e| CoreErr::IOError(e))?;  // 16
            file.write_all(&[0; 16])
                .map_err(|e| CoreErr::IOError(e))?;  // 16
            file.write_all(&header.nonce)
                .map_err(|e| CoreErr::IOError(e))?; // 20 or 14 or 8
            file.write_all(&padding)
                .map_err(|e| CoreErr::IOError(e))?; // 20 - nonce_len. This has reached the 64 bytes
        }
    }

    Ok(())
}

// this takes an input file, and gets all of the data necessary from the header of the file
// it ensures that the buffer starts at 64 bytes, so that other functions can just read encrypted data immediately
pub fn read_from_file(file: &mut File) -> Result<Header, CoreErr> {
    let mut signature = [0u8; 4];
    let mut version_info = [0u8; 2];
    let mut algorithm_info = [0u8; 2];
    let mut salt = [0u8; SALTLEN];

    file.read_exact(&mut signature)
        .map_err(|e| CoreErr::IOError(e))?;

    if signature != SIGNATURE{
        return Err(CoreErr::BadSignature)
    }
    file.read_exact(&mut version_info)
        .map_err(|e| CoreErr::IOError(e))?;
    file.read_exact(&mut algorithm_info)
        .map_err(|e| CoreErr::IOError(e))?;

    let header_info = deserialize(version_info, algorithm_info)?;
    match header_info.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];

            file.read_exact(&mut salt)
                .map_err(|e| CoreErr::IOError(e))?;
            file.read_exact(&mut [0; 16])
                .map_err(|e| CoreErr::IOError(e))?; // read and subsequently discard the next 16 bytes
            file.read_exact(&mut nonce)
                .map_err(|e| CoreErr::IOError(e))?;
            file.read_exact(&mut vec![0u8; 20 - nonce_len])
                .map_err(|e| CoreErr::IOError(e))?; // read and discard the final padding

            Ok(Header {
                header_type: header_info,
                nonce,
                salt,
            })
        }
    }
}

// this calculates how long the nonce will be, based on the provided input
fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::Aes256Gcm => 12,
        Algorithm::DeoxysII256 => 15,
    };
    nonce_len -= 4; // the last 4 bytes are dynamic in streamLE mode
    nonce_len
}

// this takes information about the header, and serializes it into raw bytes
// this is the inverse of the deserialize function
fn serialize(header_info: &HeaderType) -> ([u8; 2], [u8; 2]) {
    let version_info = match header_info.header_version {
        HeaderVersion::V1 => {
            let info: [u8; 2] = [0xDE, 0x01];
            info
        }
    };
    let algorithm_info = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let info: [u8; 2] = [0x0E, 0x01];
            info
        }
        Algorithm::Aes256Gcm => {
            let info: [u8; 2] = [0x0E, 0x02];
            info
        }
        Algorithm::DeoxysII256 => {
            let info: [u8; 2] = [0x0E, 0x03];
            info
        }
    };

    (version_info, algorithm_info)
}

// this is used for converting raw bytes from the header to enums that dexios can understand
// this involves the header version, encryption algorithm/mode, and possibly more in the future
fn deserialize(
    version_info: [u8; 2],
    algorithm_info: [u8; 2],
) -> Result<HeaderType, CoreErr> {
    let header_version = match version_info {
        [0xDE, 0x01] => HeaderVersion::V1,
        _ => return Err(CoreErr::BadHeaderVersion),
    };

    let algorithm = match algorithm_info {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::Aes256Gcm,
        [0x0E, 0x03] => Algorithm::DeoxysII256,
        _ => return Err(CoreErr::DecryptFail("Invalid algorithm".to_string())),
    };

    Ok(HeaderType {
        header_version,
        algorithm,
    })
}