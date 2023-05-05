#[cfg(test)]
mod tests;

use fennel_lib::{
    export_keypair_to_file, generate_keypair, get_session_public_key, get_session_secret,
    get_shared_secret, hash, import_keypair_from_file,
    rsa_tools::{decrypt, encrypt},
    sign, verify, AESCipher, FennelCipher, FennelRSAPublicKey,
};
use std::path::PathBuf;
use std::str;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Convenience wrapper for managing local key storage.
pub fn handle_generate_keypair() -> ([u8; 16], rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let (private_key, public_key): (rsa::RsaPrivateKey, rsa::RsaPublicKey) =
        match import_keypair_from_file(
            PathBuf::from("./Private.key"),
            PathBuf::from("./Public.key"),
        ) {
            Ok(v) => v,
            Err(_) => {
                println!("Setting up a new keypair...");
                let (private_key, public_key) = generate_keypair(4096);
                println!("Finished.");

                export_keypair_to_file(
                    &private_key,
                    &public_key,
                    PathBuf::from("./Private.key"),
                    PathBuf::from("./Public.key"),
                )
                .expect("failed to export keypair");

                (private_key, public_key)
            }
        };

    let pub_key = FennelRSAPublicKey::new(public_key).unwrap();
    let fingerprint: [u8; 16] = hash(pub_key.as_u8())[0..16].try_into().unwrap();
    (fingerprint, private_key, pub_key.pk)
}

/// Handles RSA encryption.
pub fn handle_encrypt(public_key: &str, plaintext: &str) -> Vec<u8> {
    let pub_key = FennelRSAPublicKey::from_u8(&hex::decode(public_key).unwrap()).unwrap();
    encrypt(&pub_key.pk, plaintext.as_bytes().to_vec())
}

/// Handles RSA decryption.
pub fn handle_decrypt(ciphertext: Vec<u8>, private_key: &rsa::RsaPrivateKey) -> String {
    let decrypted = decrypt(private_key, ciphertext);
    String::from(str::from_utf8(&decrypted).unwrap())
}

/// Issues a signature based on the current user's identity.
pub fn handle_sign(message: &str, private_key: rsa::RsaPrivateKey) -> String {
    hex::encode(sign(&private_key, message.as_bytes().to_vec()))
}

/// Verifies a signature based on the identity it claims to be from.
pub fn handle_verify(message: &str, signature: &str, public_key: &str) -> bool {
    let pub_key = FennelRSAPublicKey::from_u8(&hex::decode(public_key).unwrap()).unwrap();
    verify(
        &pub_key.pk,
        message.as_bytes().to_vec(),
        hex::decode::<&String>(&String::from(signature)).unwrap(),
    )
}

/// Execute shared secret derivation given Diffie-Hellman factors.
pub fn parse_shared_secret(secret: String, public_key: String) -> SharedSecret {
    let secret_key_bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
    let parsed_secret_key = StaticSecret::from(secret_key_bytes);
    let key_bytes: [u8; 32] = hex::decode(public_key).unwrap().try_into().unwrap();
    let parsed_public_key = PublicKey::from(key_bytes);
    get_shared_secret(parsed_secret_key, &parsed_public_key)
}

/// Prepare a cipher based on the user's secret key and the contact's public key.
pub fn prep_cipher(secret: String, public_key: String) -> AESCipher {
    let shared_secret = parse_shared_secret(secret, public_key);
    prep_cipher_from_secret(shared_secret.as_bytes())
}

/// Derives an AES cipher from a known shared secret.
pub fn prep_cipher_from_secret(shared_secret: &[u8; 32]) -> AESCipher {
    AESCipher::new_from_shared_secret(shared_secret)
}

/// Uses a known cipher to execute AES encryption.
pub fn handle_aes_encrypt(cipher: AESCipher, plaintext: String) -> Vec<u8> {
    cipher.encrypt(plaintext)
}

/// Uses a known cipher to execute AES decryption.
pub fn handle_aes_decrypt(cipher: AESCipher, ciphertext: Vec<u8>) -> String {
    String::from_utf8_lossy(&cipher.decrypt(ciphertext)).to_string()
}

/// Creates a secret and public key for use in Diffie-Hellman.
pub fn handle_diffie_hellman_one() -> (StaticSecret, PublicKey) {
    let secret = get_session_secret();
    let public = get_session_public_key(&secret);
    (secret, public)
}

/// Prepares a short message for transmission as a FennelServerPacket.
pub fn pack_message(mut ciphertext: Vec<u8>) -> Vec<u8> {
    let iprime: usize = ciphertext.len();
    ciphertext.resize(504, 0);
    let mut ciphertext_new = (iprime.to_ne_bytes()).to_vec();
    ciphertext_new.extend(ciphertext);
    ciphertext_new
}

/// Retrieves an original message from packet padding.
pub fn unpack_message(ciphertext: Vec<u8>) -> Vec<u8> {
    let ciphertext_lead: [u8; 8] = ciphertext[0..8].try_into().unwrap();
    let count = 8 + usize::from_ne_bytes(ciphertext_lead);
    let ciphertext_mod = &ciphertext[8..count];
    ciphertext_mod.to_vec()
}
