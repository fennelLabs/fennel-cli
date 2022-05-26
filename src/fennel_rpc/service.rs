use fennel_lib::get_identity_database_handle;
use jsonrpsee::core::{async_trait, Error};

use super::traits::FennelRPCServer;
use super::types::{FennelFingerprint, FennelPublicKeyBytes, FennelSignature};
use crate::client::{
    handle_decrypt, handle_encrypt, handle_generate_keypair, handle_sign, handle_verify,
};

pub struct FennelRPCService;

#[async_trait]
impl FennelRPCServer<FennelFingerprint, FennelSignature, FennelPublicKeyBytes>
    for FennelRPCService
{
    async fn encrypt(&self, identity: u32, plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let identity_db = get_identity_database_handle();
        Ok(handle_encrypt(
            identity_db,
            &identity,
            &String::from_utf8_lossy(&plaintext),
        ))
    }

    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (_, private_key, _) = handle_generate_keypair();
        Ok(handle_decrypt(ciphertext, &private_key).as_bytes().to_vec())
    }

    async fn sign(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (_, private_key, _) = handle_generate_keypair();
        Ok(
            handle_sign(&String::from_utf8_lossy(&ciphertext), private_key)
                .as_bytes()
                .to_vec(),
        )
    }

    async fn verify(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
        identity: u32,
    ) -> Result<bool, Error> {
        let identity_db = get_identity_database_handle();
        Ok(handle_verify(
            identity_db,
            &String::from_utf8_lossy(&message),
            &String::from_utf8_lossy(&signature),
            &identity,
        ))
    }
}
