use crate::{
    client::{handle_sign, handle_verify, parse_shared_secret, prep_cipher},
    convert_rsa,
};

use super::{
    handle_aes_decrypt, handle_aes_encrypt, handle_decrypt, handle_diffie_hellman_one,
    handle_encrypt, handle_generate_keypair,
};

#[test]
/// Tests the processes for generating keys, encrypting text, and decrypting the resulting ciphertext.
fn test_handle_encrypt_and_decrypt() {
    let (_, private_key, public_key) = handle_generate_keypair(4096);
    let key_bytes = convert_rsa(public_key);

    let result = handle_encrypt(&hex::encode(key_bytes), &String::from("test"));
    let decrypted = handle_decrypt(result, &private_key);

    assert_eq!(String::from("test"), decrypted);
}

#[test]
fn test_handle_sign_and_verify() {
    let (_, private_key, public_key) = handle_generate_keypair(4096);
    let key_bytes = convert_rsa(public_key);

    let signature = handle_sign(&String::from("Test"), private_key);
    assert_eq!(
        handle_verify(&String::from("Test"), &signature, &hex::encode(key_bytes)),
        true
    )
}

#[test]
fn test_diffie_hellman() {
    let (secret_key, public_key) = handle_diffie_hellman_one();
    let secret = hex::encode(secret_key.to_bytes());
    let public = hex::encode(public_key.to_bytes());
    let shared1 = parse_shared_secret(secret.clone(), public.clone());
    let shared2 = parse_shared_secret(secret.clone(), public.clone());
    assert_eq!(shared1.as_bytes(), shared2.as_bytes());

    let cipher = prep_cipher(secret.clone(), public.clone());
    let ciphertext = handle_aes_encrypt(cipher, String::from("This is a test."));
    let ciphertext_hex = hex::encode(ciphertext);

    let cipher = prep_cipher(secret, public);
    let plaintext = handle_aes_decrypt(cipher, hex::decode(ciphertext_hex).unwrap());

    assert_eq!(String::from("This is a test."), plaintext);
}
