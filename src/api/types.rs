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
#[derive(Debug, Deserialize)]
pub struct BigMultiplyPacket {
    pub a: Option<String>,
    pub b: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BigMultiplyResponse {
    pub success: bool,
    pub result: u128,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeriveAuthTokenPacket {
    pub secret: String,
    pub context: String,
}

#[derive(Debug, Serialize)]
pub struct DeriveAuthTokenResponse {
    pub success: bool,
    pub derived_token: Option<String>,
    pub error: Option<String>,
}

// ECDH Authentication Types
#[derive(Debug, Serialize)]
pub struct GenerateEcdhKeypairResponse {
    pub success: bool,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ComputeEcdhSharedSecretPacket {
    pub my_private_key: String,
    pub their_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct ComputeEcdhSharedSecretResponse {
    pub success: bool,
    pub shared_secret: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeriveAuthFromEcdhPacket {
    pub my_private_key: String,
    pub their_public_key: String,
    pub context: String,
}

#[derive(Debug, Serialize)]
pub struct DeriveAuthFromEcdhResponse {
    pub success: bool,
    pub shared_secret: Option<String>,
    pub derived_token: Option<String>,
    pub error: Option<String>,
}

// Brainpool ECDH Types (RFC 5639 Whiteflag Compliance)
#[derive(Debug, Serialize)]
pub struct GenerateBrainpoolKeypairResponse {
    pub success: bool,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportBrainpoolKeypairPacket {
    pub private_key: String,
}

#[derive(Debug, Serialize)]
pub struct ImportBrainpoolKeypairResponse {
    pub success: bool,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ComputeBrainpoolSharedSecretPacket {
    pub my_private_key: String,
    pub their_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct ComputeBrainpoolSharedSecretResponse {
    pub success: bool,
    pub shared_secret: Option<String>,
    pub error: Option<String>,
}

