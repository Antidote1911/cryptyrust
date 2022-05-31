use crate::constants::*;
use argon2::{Argon2, Params};
use crate::errors::*;
use crate::secret::*;
use rand::prelude::StdRng;
use rand::Rng;
use rand::SeedableRng;
use crate::header::HeaderVersion;

// this generates a salt for password hashing
pub fn gen_salt() -> [u8; SALTLEN] {
    StdRng::from_entropy().gen::<[u8; SALTLEN]>()
}

// this handles argon2 hashing with the provided key
// it returns the key hashed with a specified salt
// it also ensures that raw_key is zeroed out
pub fn argon2_hash(
    password: &Secret<String>,
    salt: &[u8; SALTLEN],
    version: &HeaderVersion,
) -> Result<Secret<[u8; 32]>, CoreErr> {
    let mut key = [0u8; 32];

    let params = match version {
        HeaderVersion::V1 => {
            // 8192KiB of memory, 8 iterations, 4 levels of parallelism
            let params = Params::new(8192, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                Ok(parameters) => parameters,
                Err(_) => return Err(CoreErr::Argon2Params),
            }
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(password.expose().as_ref(), salt, &mut key);
    if result.is_err() {
        return Err(CoreErr::Argon2Hash);
    }
    Ok(Secret::new(key))
}