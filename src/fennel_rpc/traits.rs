use jsonrpsee::core::Error;
use jsonrpsee_proc_macros::rpc;

#[rpc(server, client, namespace = "state")]
pub trait FennelRPC<Fingerprint, Signature, PublicKeyBytes> {
    #[method(name = "encrypt")]
    async fn encrypt(
        &self,
        plaintext: Vec<u8>,
        public_key_bytes: PublicKeyBytes,
    ) -> Result<Vec<u8>, Error>;

    #[method(name = "decrypt")]
    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error>;

    #[method(name = "sign")]
    async fn sign(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error>;

    #[method(name = "verify")]
    async fn verify(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key_bytes: PublicKeyBytes,
    ) -> Result<bool, Error>;
}
