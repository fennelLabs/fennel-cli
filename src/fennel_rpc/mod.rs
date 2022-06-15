mod types;

use crate::client::{handle_decrypt, handle_generate_keypair, handle_sign};
use fennel_lib::{encrypt, export_public_key_to_binary, import_public_key_from_binary, verify};
use jsonrpsee::ws_server::{RpcModule, WsServerBuilder};
use std::net::SocketAddr;

use self::types::{EncryptionPacket, DecryptionPacket, SignPacket, VerifyPacket};

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
        Ok(public_key_bytes.to_vec())
    })?;

    module.register_method("encrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: EncryptionPacket = serde_json::from_str(&json).expect("JSON was misformatted.");
        
        let public_key_bytes: Vec<u8> = params_struct.public_key_bytes.into_bytes();
        let plaintext: Vec<u8> = params_struct.plaintext.into_bytes();

        let public_key =
            import_public_key_from_binary(&public_key_bytes.try_into().unwrap()).unwrap();
        Ok(encrypt(public_key, plaintext))
    })?;

    module.register_method("decrypt", |params, _| {
        let json: String = params.parse()?;
        let params_struct: DecryptionPacket = serde_json::from_str(&json).expect("JSON was misformatted.");

        let ciphertext = params_struct.ciphertext.into_bytes();

        let (_, private_key, _) = handle_generate_keypair();
        Ok(handle_decrypt(ciphertext, &private_key).as_bytes().to_vec())
    })?;

    module.register_method("sign", |params, _| {
        let json: String = params.parse()?;
        let params_struct: SignPacket = serde_json::from_str(&json).expect("JSON was misformatted.");

        let message = params_struct.message.as_bytes();

        let (_, private_key, _) = handle_generate_keypair();
        Ok(handle_sign(&String::from_utf8_lossy(&message), private_key)
            .as_bytes()
            .to_vec())
    })?;

    module.register_method("verify", |params, _| {
        let json: String = params.parse()?;
        let params_struct: VerifyPacket = serde_json::from_str(&json).expect("JSON was misformatted.");
        
        let public_key_bytes: Vec<u8> = params_struct.public_key_bytes.into_bytes();
        let message: Vec<u8> = params_struct.message.into_bytes();
        let signature: Vec<u8> = params_struct.signature.into_bytes();

        let public_key =
            import_public_key_from_binary(&public_key_bytes.try_into().unwrap()).unwrap();
        Ok(verify(public_key, message, signature))
    })?;

    module.register_method("whiteflag_encode", |params, _| {
        let json: String = params.parse()?;
        let hex = whiteflag_rust::encode_from_json(&json).unwrap();
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
