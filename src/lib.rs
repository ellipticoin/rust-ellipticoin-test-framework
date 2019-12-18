extern crate hex;
extern crate rand;
extern crate secp256k1;

use self::rand::{thread_rng, Rng};
use self::secp256k1::Message;
mod constants;
pub use constants::*;

pub fn random_bytes(length: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter::<u8>().take(length).collect()
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signer = secp256k1::Secp256k1::new();
    let (private_key, public_key) = signer.generate_keypair(&mut thread_rng());

    (private_key[..].to_vec(), public_key.serialize().to_vec())
}

pub fn secp256k1_sign_recoverable(message_vec: Vec<u8>, private_key_vec: Vec<u8>) -> (u8, Vec<u8>) {
    let signer = secp256k1::Secp256k1::new();
    let message = Message::from_slice(&message_vec).unwrap();
    let private_key = secp256k1::SecretKey::from_slice(&private_key_vec).unwrap();
    let (recovery_id, signature) = signer
        .sign_recoverable(&message, &private_key)
        .serialize_compact();
    (recovery_id.to_i32() as u8, signature.to_vec())
}
