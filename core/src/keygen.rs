use std::error;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version, Params};
use crypto_secretstream::Key;

use crate::KEYBYTES;

pub fn get_argon2_key(password: &str, salt: &SaltString) -> Result<Key, Box<dyn error::Error>> {
    let params = argon2_params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut buffer = [0u8; 32];
    argon2.hash_password_into(&password.as_bytes(), &salt.as_bytes(), &mut buffer).map_err(|e| e.to_string())?;
    Ok(Key::try_from(buffer.as_ref()).unwrap())
}

fn argon2_params() -> Params {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(0x10000).unwrap();
    builder.t_cost(2).unwrap();
    builder.p_cost(4).unwrap();
    builder.output_len(KEYBYTES).unwrap();

    builder.params().unwrap()
}