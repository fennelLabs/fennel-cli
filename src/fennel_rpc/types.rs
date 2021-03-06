use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct GenerateEncryptionChannelResponse {
    pub secret: String,
    pub public: String,
}

#[derive(Debug, Deserialize)]
pub struct AcceptEncryptionChannelPacket {
    pub secret: String,
    pub public: String,
}

#[derive(Debug, Serialize)]
pub struct AcceptEncryptionChannelResponse {
    pub shared_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct DhEncryptPacket {
    pub plaintext: String,
    pub shared_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct DhDecryptPacket {
    pub ciphertext: String,
    pub shared_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptionPacket {
    pub public_key_bytes: String,
    pub plaintext: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptionPacket {
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct SignPacket {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPacket {
    pub public_key_bytes: String,
    pub message: String,
    pub signature: String,
}
