use fennel_lib::{get_identity_database_handle, get_message_database_handle, FennelServerPacket};
use jsonrpsee::core::{async_trait, Error};
use tokio::net::TcpStream;

use super::traits::FennelRPCServer;
use super::types::{FennelFingerprint, FennelPublicKeyBytes, FennelSignature};
use crate::client::{handle_connection, handle_encrypt, handle_generate_keypair, handle_decrypt};

pub struct FennelRPCService;

#[async_trait]
impl FennelRPCServer<FennelFingerprint, FennelSignature, FennelPublicKeyBytes>
    for FennelRPCService
{
    async fn create_identity(
        &self,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error> {
        let packet = FennelServerPacket {
            command: [0; 1],
            identity: [0; 4],
            fingerprint,
            message: [0; 512],
            signature: signature.try_into().unwrap(),
            public_key: public_key_bytes.try_into().unwrap(),
            recipient: [0; 4],
            message_type: [0; 1],
        };
        let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
        let identity_db = get_identity_database_handle();
        let message_db = get_message_database_handle();
        handle_connection(identity_db, message_db, listener, packet).await?;
        Ok("Identity created successfully".as_bytes().to_vec())
    }

    async fn retrieve_identity(
        &self,
        identity_id: u32,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error> {
        let packet = FennelServerPacket {
            command: [3; 1],
            identity: identity_id.to_ne_bytes(),
            fingerprint,
            message: [0; 512],
            signature: signature.try_into().unwrap(),
            public_key: public_key_bytes.try_into().unwrap(),
            recipient: [0; 4],
            message_type: [0; 1],
        };
        let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
        let identity_db = get_identity_database_handle();
        let message_db = get_message_database_handle();
        handle_connection(identity_db, message_db, listener, packet).await?;
        Ok("Identity information updated".as_bytes().to_vec())
    }

    async fn send_message(
        &self,
        sender_id: u32,
        recipient_id: u32,
        ciphertext: Vec<u8>,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error> {
        let packet = FennelServerPacket {
            command: [1; 1],
            identity: sender_id.to_ne_bytes(),
            fingerprint,
            message: ciphertext.to_owned().try_into().unwrap(),
            signature: signature.try_into().unwrap(),
            public_key: public_key_bytes.try_into().unwrap(),
            recipient: recipient_id.to_ne_bytes(),
            message_type: [1; 1],
        };
        let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
        let identity_db = get_identity_database_handle();
        let message_db = get_message_database_handle();
        handle_connection(identity_db, message_db, listener, packet).await?;
        Ok("Message sent".as_bytes().to_vec())
    }

    async fn get_messages(
        &self,
        id: u32,
        fingerprint: FennelFingerprint,
        signature: FennelSignature,
        public_key_bytes: FennelPublicKeyBytes,
    ) -> Result<Vec<u8>, Error> {
        let packet = FennelServerPacket {
            command: [2; 1],
            identity: id.to_ne_bytes(),
            fingerprint,
            message: [0; 512],
            signature: signature.try_into().unwrap(),
            public_key: public_key_bytes.try_into().unwrap(),
            recipient: [0; 4],
            message_type: [0; 1],
        };
        let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
        let identity_db = get_identity_database_handle();
        let message_db = get_message_database_handle();
        handle_connection(identity_db, message_db, listener, packet).await?;
        Ok("Messages received".as_bytes().to_vec())
    }

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
}
