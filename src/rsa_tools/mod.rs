#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;

use rand::rngs::OsRng;
use rsa::pkcs1::FromRsaPublicKey;
use rsa::pkcs1::ToRsaPublicKey;
use rsa::pkcs8::Error;
use rsa::Hash::SHA3_512;
use rsa::{
    pkcs8::FromPrivateKey, pkcs8::FromPublicKey, pkcs8::ToPrivateKey, pkcs8::ToPublicKey,
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use sha3::{Digest, Sha3_512};
use std::hash::Hash;

pub fn hash<H: Hash + AsRef<[u8]>>(text: H) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(text);
    hasher.finalize().to_vec()
}

/// Generate a public/private keypair and return it as RSA structs.
#[allow(unused)]
pub fn generate_keypair(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

/// Given plaintext, encrypt it with the provided public key.
#[allow(unused)]
pub fn encrypt(public_key: RsaPublicKey, plaintext: Vec<u8>) -> Vec<u8> {
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    public_key
        .encrypt(&mut rng, padding, &plaintext[..])
        .expect("failed to encrypt")
}

/// Given a private key, decrypt ciphertext produced with its related public key.
#[allow(unused)]
pub fn decrypt(private_key: RsaPrivateKey, ciphertext: Vec<u8>) -> Vec<u8> {
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    private_key
        .decrypt(padding, &ciphertext)
        .expect("failed to decrypt")
}

// Issue a signature from `private_key` on `message`.
#[allow(unused)]
pub fn sign(private_key: RsaPrivateKey, message: Vec<u8>) -> Vec<u8> {
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(SHA3_512));
    let digest = hash(&message);
    private_key.sign(padding, &digest).expect("failed to sign")
}

/// Verify that a signature for a message is valid.
pub fn verify(public_key: RsaPublicKey, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(SHA3_512));
    let result = hash(&message);
    public_key.verify(padding, &result, &signature).is_ok()
}

/// Read in a keypair from a file.
#[allow(unused)]
pub fn import_keypair_from_file(
    private_keyfile_path: std::path::PathBuf,
    public_keyfile_path: std::path::PathBuf,
) -> Result<(RsaPrivateKey, RsaPublicKey), Error> {
    let pri = RsaPrivateKey::read_pkcs8_pem_file(private_keyfile_path)?;
    let pbk = RsaPublicKey::read_public_key_pem_file(public_keyfile_path)?;
    Ok((pri, pbk))
}

/// Write an in-memory keypair out to a file.
#[allow(unused)]
pub fn export_keypair_to_file(
    private_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
    private_keyfile_path: std::path::PathBuf,
    public_keyfile_path: std::path::PathBuf,
) -> Result<(), Error> {
    RsaPrivateKey::write_pkcs8_pem_file(private_key, private_keyfile_path)?;
    RsaPublicKey::write_public_key_pem_file(public_key, public_keyfile_path)?;
    Ok(())
}

/// Read in a public key from a file.
pub fn import_public_key_from_binary(
    public_key_binary: &[u8; 1038],
) -> Result<RsaPublicKey, Error> {
    let public_key = RsaPublicKey::from_pkcs1_der(public_key_binary)?;
    Ok(public_key)
}

#[allow(unused)]
pub fn export_public_key_to_binary(public_key: &RsaPublicKey) -> Result<[u8; 1038], Error> {
    let public_key_binary = RsaPublicKey::to_pkcs1_der(public_key).unwrap();
    let public_key_ref = public_key_binary.as_der();
    let public_key_array: [u8; 1038] = match public_key_ref.try_into() {
        Ok(v) => v,
        Err(e) => {
            println!("{}", public_key_ref.len());
            panic!("{}", e);
        }
    };
    Ok(public_key_array)
}
