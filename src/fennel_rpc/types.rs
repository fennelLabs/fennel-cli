use serde::Deserialize;

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
