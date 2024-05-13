use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct WhiteflagEncodeResponse {
    pub success: bool,
    pub encoded: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhiteflagDecodeResponse {
    pub success: bool,
    pub decoded: Option<String>,
    pub error: Option<String>,
}

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
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SignPacket {
    pub message: String,
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPacket {
    pub public_key_bytes: String,
    pub message: String,
    pub signature: String,
}
<<<<<<< HEAD
<<<<<<< Updated upstream
=======

#[derive(Debug, Deserialize)]
pub struct BigMultiplyPacket {
    pub a: Option<String>,
    pub b: Option<String>,
=======

#[derive(Debug, Deserialize)]
pub struct BigMultiplyPacket {
    pub a: u128,
    pub b: u128,
>>>>>>> 1764ff1440f073dbd64fba4173cb78d34f4c8c03
}

#[derive(Debug, Serialize)]
pub struct BigMultiplyResponse {
    pub success: bool,
    pub result: u128,
    pub error: Option<String>,
<<<<<<< HEAD
}
>>>>>>> Stashed changes
=======
}
>>>>>>> 1764ff1440f073dbd64fba4173cb78d34f4c8c03
