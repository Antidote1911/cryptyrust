use crate::constants::*;
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use crate::errors::*;
use crate::secret::*;
use rand::prelude::StdRng;
use rand::Rng;
use rand::SeedableRng;
use crate::DeriveStrength;
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
    _version: &HeaderVersion,
    derivestrength: &DeriveStrength
) -> Result<Secret<[u8; KEYLEN]>, CoreErr> {

    let params = match derivestrength {
        DeriveStrength::Interactive => argon2_params_interactive(),
        DeriveStrength::Moderate    => argon2_params_moderate(),
        DeriveStrength::Sensitive   => argon2_params_sensitive(),
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEYLEN];
    argon2.hash_password_into(password.expose().as_ref(), salt, &mut key).map_err(|_|CoreErr::Argon2Hash)?;
    Ok(Secret::new(key))
}

fn argon2_params_interactive() -> Params {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(ARGON2_INTERACTIVE_MEMORY).expect("INVALID ARGON2 MEMORY");
    builder.t_cost(ARGON2_INTERACTIVE_ITERATIONS).expect("INVALID ARGON2 ITERATION");
    builder.p_cost(ARGON2_INTERACTIVE_PARALELISM).expect("INVALID ARGON2 PARALELISM");
    builder.output_len(KEYLEN).expect("INVALID ARGON2 KEYLEN");
    builder.params().unwrap()
}

fn argon2_params_moderate() -> Params {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(ARGON2_MODERATE_MEMORY).expect("INVALID ARGON2 MEMORY");
    builder.t_cost(ARGON2_MODERATE_ITERATIONS).expect("INVALID ARGON2 ITERATION");
    builder.p_cost(ARGON2_MODERATE_PARALELISM).expect("INVALID ARGON2 PARALELISM");
    builder.output_len(KEYLEN).expect("INVALID ARGON2 KEYLEN");
    builder.params().unwrap()
}

fn argon2_params_sensitive() -> Params {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(ARGON2_SENSITIVE_MEMORY).expect("INVALID ARGON2 MEMORY");
    builder.t_cost(ARGON2_SENSITIVE_ITERATIONS).expect("INVALID ARGON2 ITERATION");
    builder.p_cost(ARGON2_SENSITIVE_PARALELISM).expect("INVALID ARGON2 PARALELISM");
    builder.output_len(KEYLEN).expect("INVALID ARGON2 KEYLEN");
    builder.params().unwrap()
}