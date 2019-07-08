extern crate hex;
extern crate rand;
extern crate secp256k1;

extern crate lazy_static;
use self::rand::{Rng, thread_rng};
use self::secp256k1::Message;

pub fn alice() -> Vec<u8> {
    hex::decode("02abc074b9843c9d41fe5c46df8a4df6f46309aed0b6620c59ec22a4dcc5e19001").unwrap()
}
pub fn alices_private_key() -> Vec<u8> {
    hex::decode("b13462163b5185910e9bad08a02f5fdcc81ce58c97e0d1858172e9437fa8f68a").unwrap()
}
pub fn bob() -> Vec<u8> {
    hex::decode("03dfde758e12e270c190accfee9f3919f47b22f2b1861132909d066f842bcff002").unwrap()
}
pub fn bobs_private_key() -> Vec<u8> {
    hex::decode("1a9d9a652edaf6b808b2305d2b5cac4b152f21a531fcd9143f94c7e7c8189184").unwrap()
}
pub fn carol() -> Vec<u8> {
    hex::decode("035f17c105e9457f23b1c96283c34d99439817fe4f0e838b7ce5c4fef972430003").unwrap()
}
pub fn carols_private_key() -> Vec<u8> {
    hex::decode("9cb1988f218d38b73ae096445b07103fd2c4cd54c094adc0c3e079ef5398f2b2").unwrap()
}
pub fn dave() -> Vec<u8> {
    hex::decode("03115586862a6f4bba22ace69395eeda178404da44f9eda76ca0896b222af8c004").unwrap()
}
pub fn daves_private_key() -> Vec<u8> {
    hex::decode("6f200f464a1fb18851adad770a357f34af426f9ac2207bc90c134e742b79643f").unwrap()
}
pub fn eve() -> Vec<u8> {
    hex::decode("0332141bea1c04616da707e8b1495ac583cb3e8aa694289019070b3483149e5005").unwrap()
}
pub fn eves_private_key() -> Vec<u8> {
    hex::decode("394a836cceb63a88d28440891c42e96664b966d7216e26931fea9e3ec00b8254").unwrap()
}
pub fn frank() -> Vec<u8> {
    hex::decode("036f3b38df5dce545f47300573521bc54a9036aa7162c4184ee2aa45031b407006").unwrap()
}
pub fn frank_private_key() -> Vec<u8> {
    hex::decode("f963a8763606dfd48a65cacef8c2660f786e6e5a8e785d55b7631ea357e8692f").unwrap()
}
pub fn mallory() -> Vec<u8> {
    hex::decode("039ee96da4b405581bbf7c25a2fc3e12017a55c08a07c374dfe09473c875227bad").unwrap()
}
pub fn mallorys_private_key() -> Vec<u8> {
    hex::decode("e5a386094cac73c84c6cd0e52e21522446b915b7dfcc752ec6cb3d65ec0e2d01").unwrap()
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    rand::thread_rng()
    .gen_iter::<u8>()
    .take(length)
    .collect()
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
    let (recovery_id, signature) = signer.sign_recoverable(&message, &private_key).serialize_compact();
    (recovery_id.to_i32() as u8, signature.to_vec())
}
