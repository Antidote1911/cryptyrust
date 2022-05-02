use crate::constants::*;
use std::error;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version, Params};

pub fn get_argon2_key(password: &str, salt: &[u8; SALTLEN]) -> Result<[u8; KEYLEN], Box<dyn error::Error>> {
    let params = argon2_params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut buffer = [0u8; KEYLEN];
    argon2.hash_password_into(&password.as_bytes(), salt, &mut buffer).map_err(|e| e.to_string())?;
    Ok(buffer)
}

fn argon2_params() -> Params {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(ARGON2MEMORY).expect("INVALID ARGON2 MEMORY");
    builder.t_cost(ARGON2ITERATIONS).expect("INVALID ARGON2 ITERATION");
    builder.p_cost(ARGON2PARALELISM).expect("INVALID ARGON2 PARALELISM");
    builder.output_len(KEYLEN).expect("INVALID ARGON2 KEYLEN");
    builder.params().unwrap()
}