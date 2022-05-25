use jsonrpsee::core::Error;
use jsonrpsee_proc_macros::rpc;

use super::types::{FennelFingerprint, FennelPublicKeyBytes, FennelSignature};

#[rpc(server, client, namespace = "state")]
pub trait FennelRPC<Fingerprint, Signature, PublicKeyBytes> {
    #[method(name = "create_identity")]
    async fn create_identity(
        &self,
        fingerprint: Fingerprint,
        signature: Signature,
        public_key_bytes: PublicKeyBytes,
    ) -> Result<Vec<u8>, Error>;

    #[method(name = "retrieve_identity")]
    async fn retrieve_identity(
        &self,
        identity_id: u32,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error>;

    #[method(name = "send_message")]
    async fn send_message(
        &self,
        sender_id: u32,
        recipient_id: u32,
        ciphertext: Vec<u8>,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error>;

    #[method(name = "get_messages")]
    async fn get_messages(
        &self,
        id: u32,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error>;

    #[method(name = "encrypt")]
    async fn encrypt(&self, identity: u32, plaintext: Vec<u8>) -> Result<Vec<u8>, Error>;

    #[method(name = "decrypt")]
    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error>;
}
