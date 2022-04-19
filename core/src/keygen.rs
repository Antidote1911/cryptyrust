use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::pwhash::argon2id13::*;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::Key;
use sodiumoxide::crypto::secretstream::KEYBYTES;

pub fn key_derive_from_pass(pass: &str, salt: Option<Salt>) -> (Salt, Key) {
    sodiumoxide::init().expect("Unable to initialize libsodium.");
    let mut key = [0u8; KEYBYTES];
    let salt = match salt {
        Some(salt) => salt,
        None => argon2id13::gen_salt(),
    };
    argon2id13::derive_key(
        &mut key,
        pass.as_bytes(),
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .expect("Unable to derive key from password");
    let key = Key(key);
    (salt, key)
}
