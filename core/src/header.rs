use crate::errors::*;
use crate::{Algorithm, DeriveStrength, MAGICNUMBER, SALTLEN};
use blake3::Hasher;
use std::io::{Read, Write};

pub enum HeaderVersion {
    V1,
}

pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub algorithm: Algorithm,
    pub derive: DeriveStrength,
}

pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: [u8; SALTLEN],
}

pub fn write_to_file<W: Write>(file: &mut W, header: &Header) -> Result<(), CoreErr> {
    let nonce_len = calc_nonce_len(&header.header_type);

    match &header.header_type.header_version {
        HeaderVersion::V1 => {
            let padding = vec![0u8; 22 - nonce_len];
            let (version_info, algorithm_info, derive_info) = serialize(&header.header_type);

            file.write_all(&MAGICNUMBER)?; // 4
            file.write_all(&version_info)?; // 2
            file.write_all(&algorithm_info)?; // 2
            file.write_all(&derive_info)?; // 2
            file.write_all(&header.salt)?; // 16
            file.write_all(&[0; 16])?; // 16
            file.write_all(&header.nonce)?; // 8 or 20
            file.write_all(&padding)?; // 22 - nonce_len → total 64 bytes
        }
    }
    Ok(())
}

pub fn read_from_file<R: Read>(file: &mut R) -> Result<(Header, Vec<u8>), CoreErr> {
    let mut magicnumber = [0u8; 4];
    let mut version_info = [0u8; 2];
    let mut algorithm_info = [0u8; 2];
    let mut derive_info = [0u8; 2];
    let mut salt = [0u8; SALTLEN];

    file.read_exact(&mut magicnumber)?;

    if magicnumber != MAGICNUMBER {
        return Err(CoreErr::BadSignature);
    }

    file.read_exact(&mut version_info)?;
    file.read_exact(&mut algorithm_info)?;
    file.read_exact(&mut derive_info)?;

    let header_info = deserialize(version_info, algorithm_info, derive_info)?;
    match header_info.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];
            let mut padding1 = [0u8; 16];
            let mut padding2 = vec![0u8; 22 - nonce_len];

            file.read_exact(&mut salt)?;
            file.read_exact(&mut padding1)?;
            file.read_exact(&mut nonce)?;
            file.read_exact(&mut padding2)?;

            let header = Header {
                header_type: header_info,
                nonce,
                salt,
            };
            let aad = get_aad(&header, Some(padding1), Some(padding2));
            Ok((header, aad))
        }
    }
}

fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let nonce_len = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::Aes256Gcm => 12,
        Algorithm::Aes256GcmSiv => 12,
    };
    nonce_len - 4 // last 4 bytes are reserved for the LE31 stream counter
}

fn serialize(header_info: &HeaderType) -> ([u8; 2], [u8; 2], [u8; 2]) {
    let version_info = match header_info.header_version {
        HeaderVersion::V1 => [0xDE, 0x01],
    };

    let algorithm_info = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => [0x0E, 0x01],
        Algorithm::Aes256Gcm => [0x0E, 0x02],
        Algorithm::Aes256GcmSiv => [0x0E, 0x03],
    };

    let derive_info = match header_info.derive {
        DeriveStrength::Interactive => [0xBE, 0x01],
        DeriveStrength::Moderate => [0xBE, 0x02],
        DeriveStrength::Sensitive => [0xBE, 0x03],
    };

    (version_info, algorithm_info, derive_info)
}

fn deserialize(
    version_info: [u8; 2],
    algorithm_info: [u8; 2],
    derive_info: [u8; 2],
) -> Result<HeaderType, CoreErr> {
    let header_version = match version_info {
        [0xDE, 0x01] => HeaderVersion::V1,
        _ => return Err(CoreErr::BadHeaderVersion),
    };

    let algorithm = match algorithm_info {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::Aes256Gcm,
        [0x0E, 0x03] => Algorithm::Aes256GcmSiv,
        _ => return Err(CoreErr::DecryptFail("Invalid algorithm".to_string())),
    };

    let derive = match derive_info {
        [0xBE, 0x01] => DeriveStrength::Interactive,
        [0xBE, 0x02] => DeriveStrength::Moderate,
        [0xBE, 0x03] => DeriveStrength::Sensitive,
        _ => return Err(CoreErr::DecryptFail("Invalid DeriveStrength".to_string())),
    };

    Ok(HeaderType {
        header_version,
        algorithm,
        derive,
    })
}

pub fn hash(hasher: &mut Hasher, header: &Header) {
    match &header.header_type.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 22 - nonce_len];
            let (version_info, algorithm_info, derive_info) = serialize(&header.header_type);

            hasher.update(&MAGICNUMBER);
            hasher.update(&version_info);
            hasher.update(&algorithm_info);
            hasher.update(&derive_info);
            hasher.update(&header.salt);
            hasher.update(&[0; 16]);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
    }
}

pub fn get_aad(header: &Header, padding1: Option<[u8; 16]>, padding2: Option<Vec<u8>>) -> Vec<u8> {
    match header.header_type.header_version {
        HeaderVersion::V1 => {
            let (version_info, algorithm_info, derive_info) = serialize(&header.header_type);

            let mut header_bytes = version_info.to_vec();
            header_bytes.extend_from_slice(&MAGICNUMBER);
            header_bytes.extend_from_slice(&algorithm_info);
            header_bytes.extend_from_slice(&derive_info);
            header_bytes.extend_from_slice(&header.salt);
            header_bytes.extend_from_slice(&padding1.unwrap());
            header_bytes.extend_from_slice(&header.nonce);
            header_bytes.extend_from_slice(&padding2.unwrap());
            header_bytes
        }
    }
}

pub fn create_aad(header: &Header) -> Vec<u8> {
    match header.header_type.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let (version_info, algorithm_info, derive_info) = serialize(&header.header_type);

            let mut header_bytes = version_info.to_vec();
            header_bytes.extend_from_slice(&MAGICNUMBER);
            header_bytes.extend_from_slice(&algorithm_info);
            header_bytes.extend_from_slice(&derive_info);
            header_bytes.extend_from_slice(&header.salt);
            header_bytes.extend_from_slice(&[0; 16]);
            header_bytes.extend_from_slice(&header.nonce);
            header_bytes.extend_from_slice(&vec![0; 22 - nonce_len]);
            header_bytes
        }
    }
}
