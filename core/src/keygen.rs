use crate::constants::*;
use argon2::{Algorithm, Argon2, Params, Version};
use crate::errors::*;
use crate::secret::*;
use rand::prelude::StdRng;
use rand::Rng;
use rand::SeedableRng;
use crate::DeriveStrength;
use crate::header::HeaderVersion;

pub fn gen_salt() -> [u8; SALTLEN] {
    StdRng::from_os_rng().random::<[u8; SALTLEN]>()
}

pub fn argon2_hash(
    password: &Secret<String>,
    salt: &[u8; SALTLEN],
    _version: &HeaderVersion,
    derivestrength: &DeriveStrength,
) -> Result<Secret<[u8; KEYLEN]>, CoreErr> {
    let params = match derivestrength {
        DeriveStrength::Interactive => Params::new(ARGON2_INTERACTIVE_MEMORY, ARGON2_INTERACTIVE_ITERATIONS, ARGON2_INTERACTIVE_PARALELISM, Some(KEYLEN)),
        DeriveStrength::Moderate    => Params::new(ARGON2_MODERATE_MEMORY,    ARGON2_MODERATE_ITERATIONS,    ARGON2_MODERATE_PARALELISM,    Some(KEYLEN)),
        DeriveStrength::Sensitive   => Params::new(ARGON2_SENSITIVE_MEMORY,   ARGON2_SENSITIVE_ITERATIONS,   ARGON2_SENSITIVE_PARALELISM,   Some(KEYLEN)),
    }.map_err(|_| CoreErr::Argon2Params)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEYLEN];
    argon2.hash_password_into(password.expose().as_ref(), salt, &mut key)
        .map_err(|_| CoreErr::Argon2Hash)?;
    Ok(Secret::new(key))
}
