mod types;

use std::panic;

use crate::client::{
    handle_aes_decrypt, handle_aes_encrypt, handle_decrypt, handle_diffie_hellman_one,
    handle_diffie_hellman_two, handle_generate_keypair, handle_sign, pack_message,
    prep_cipher_from_secret, unpack_message,
};
use fennel_lib::{encrypt, export_public_key_to_binary, import_public_key_from_binary, verify};
use jsonrpsee::ws_server::{RpcModule, WsServerBuilder};
use std::net::SocketAddr;

use self::types::{
    AcceptEncryptionChannelPacket, AcceptEncryptionChannelResponse, DecryptionPacket,
    DhDecryptPacket, DhEncryptPacket, EncryptionPacket, GenerateEncryptionChannelResponse,
    SignPacket, VerifyPacket,
};

#[allow(unreachable_code)]
pub async fn start_rpc() -> anyhow::Result<()> {
    let server = WsServerBuilder::default()
        .build("127.0.0.1:9030".parse::<SocketAddr>()?)
        .await?;

    let mut module = RpcModule::new(());
    module.register_method("hello_there", |_, _| Ok("General Kenobi!"))?;

    module.register_method("get_or_generate_keypair", |_, _| {
        let (_, _, public_key) = handle_generate_keypair();
        let public_key_bytes = match export_public_key_to_binary(&public_key) {
            Ok(bytestring) => bytestring,
            Err(error) => panic!(
                "Problem with exporting a public key to a bytestring: {}",
                error
            ),
        };
        Ok(hex::encode(public_key_bytes.to_vec()))
    })?;

    module.register_method("generate_encryption_channel", |_, _| {
        let (secret, public) = handle_diffie_hellman_one();
        Ok(GenerateEncryptionChannelResponse {
            secret: hex::encode(secret.to_bytes()),
            public: hex::encode(public.to_bytes()),
        })
    })?;

    module.register_method("accept_encryption_channel", |params, _| {
        let json: String = params.parse()?;
        let params_struct: AcceptEncryptionChannelPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");
        let shared_secret = handle_diffie_hellman_two(
            params_struct.secret.to_string(),
            params_struct.public.to_string(),
        );
        Ok(AcceptEncryptionChannelResponse {
            shared_secret: hex::encode(shared_secret.to_bytes()),
        })
    })?;

    module.register_method("dh_encrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: DhEncryptPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");
        let shared_secret: [u8; 32] = hex::decode(params_struct.shared_secret)
            .unwrap()
            .try_into()
            .expect("Unable to match shared secret to a length of 32 bytes.");
        let cipher = prep_cipher_from_secret(&shared_secret);
        let ciphertext = handle_aes_encrypt(cipher, params_struct.plaintext.to_string());
        Ok(hex::encode(pack_message(ciphertext)))
    })?;

    module.register_method("dh_decrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: DhDecryptPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");
        let ciphertext_mod = unpack_message(params_struct.ciphertext.into_bytes());
        let shared_secret: [u8; 32] = hex::decode(params_struct.shared_secret)
            .unwrap()
            .try_into()
            .expect("Unable to match shared secret to a length of 32 bytes.");
        let cipher = prep_cipher_from_secret(&shared_secret);
        Ok(handle_aes_decrypt(cipher, ciphertext_mod.to_vec()))
    })?;

    module.register_method("encrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: EncryptionPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");

        let public_key_bytes: Vec<u8> = params_struct.public_key_bytes.into_bytes();
        let plaintext: Vec<u8> = params_struct.plaintext.into_bytes();

        let public_key =
            import_public_key_from_binary(&public_key_bytes.try_into().unwrap()).unwrap();
        Ok(hex::encode(encrypt(public_key, plaintext)))
    })?;

    module.register_method("decrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: DecryptionPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");

        let ciphertext = params_struct.ciphertext.into_bytes();

        let (_, private_key, _) = handle_generate_keypair();
        Ok(hex::encode(
            handle_decrypt(ciphertext, &private_key).as_bytes().to_vec(),
        ))
    })?;

    module.register_method("sign", |params, _| {
        let json: String = params.parse()?;
        let params_struct: SignPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");

        let message = params_struct.message.as_bytes();

        let (_, private_key, _) = handle_generate_keypair();
        Ok(hex::encode(
            handle_sign(&String::from_utf8_lossy(&message), private_key)
                .as_bytes()
                .to_vec(),
        ))
    })?;

    module.register_method("verify", |params, _| {
        let json: String = params.parse()?;
        let params_struct: VerifyPacket =
            serde_json::from_str(&json).expect("JSON was misformatted.");

        let public_key_bytes: Vec<u8> = params_struct.public_key_bytes.into_bytes();
        let message: Vec<u8> = params_struct.message.into_bytes();
        let signature: Vec<u8> = params_struct.signature.into_bytes();

        let public_key =
            import_public_key_from_binary(&public_key_bytes.try_into().unwrap()).unwrap();
        Ok(verify(public_key, message, signature))
    })?;

    module.register_method("whiteflag_encode", |params, _| {
        let json: String = params.parse()?;
        let result = panic::catch_unwind(|| whiteflag_rust::encode_from_json(&json).unwrap());
        let hex = match result {
            Ok(v) => v,
            Err(e) => format!("{:?}", e),
        };
        Ok(hex)
    })?;

    module.register_method("whiteflag_decode", |params, _| {
        let hex: String = params.parse()?;
        let message = whiteflag_rust::decode_from_hex(hex).unwrap();
        Ok(message)
    })?;

    server.local_addr()?;
    server.start(module)?;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    Ok(())
}
