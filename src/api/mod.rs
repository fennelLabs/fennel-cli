#[cfg(test)]
mod tests;

use std::{collections::HashMap, panic};

use serde_json::json;
use warp::Filter;

mod types;

use crate::{
    api::types::BigMultiplyResponse,
    client::{
        handle_aes_decrypt, handle_aes_encrypt, handle_decrypt, handle_diffie_hellman_one,
        handle_generate_keypair, handle_sign, parse_shared_secret, prep_cipher_from_secret,
    },
};
use fennel_lib::{encrypt, verify, FennelRSAPrivateKey, FennelRSAPublicKey};

fn hashmap_to_json_string(map: HashMap<String, String>) -> String {
    let mut json_string = String::from("{");
    for (key, value) in map {
        json_string.push_str(&format!("\"{}\":\"{}\",", key, value));
    }
    json_string.pop();
    json_string.push('}');
    json_string
}

async fn hello_there() -> Result<impl warp::Reply, warp::Rejection> {
    println!("Hello there!");
    let r = json!("General Kenobi!");
    Ok(warp::reply::json(&r))
}

async fn generate_keypair() -> Result<impl warp::Reply, warp::Rejection> {
    println!("Generating keypair...");
    let (_, _, public_key) = handle_generate_keypair(4096);

    let public_key_bytes = match FennelRSAPublicKey::new(public_key) {
        Ok(bytestring) => bytestring,
        Err(error) => panic!(
            "Problem with exporting a public key to a bytestring: {}",
            error
        ),
    };
    let r = json!(hex::encode(public_key_bytes.as_u8()));
    Ok(warp::reply::json(&r))
}

async fn generate_encryption_channel() -> Result<impl warp::Reply, warp::Rejection> {
    println!("Generating encryption channel...");
    let (secret, public) = handle_diffie_hellman_one();
    let r = types::GenerateEncryptionChannelResponse {
        secret: hex::encode(secret.to_bytes()),
        public: hex::encode(public.to_bytes()),
    };
    Ok(warp::reply::json(&r))
}

async fn rsa_encrypt(json: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Encrypting message...");
    let params_struct: types::EncryptionPacket =
        serde_json::from_str(&json).expect("JSON was misformatted.");

    let public_key_bytes: Vec<u8> = hex::decode(params_struct.public_key_bytes).unwrap();
    let plaintext: Vec<u8> = params_struct.plaintext.into_bytes();

    let public_key = FennelRSAPublicKey::from_u8(&public_key_bytes).unwrap();
    Ok(hex::encode(encrypt(&public_key.pk, plaintext)))
}

async fn rsa_decrypt(json: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Decrypting message...");
    let params_struct: types::DecryptionPacket =
        serde_json::from_str(&json).expect("JSON was misformatted.");

    let ciphertext = hex::decode(params_struct.ciphertext).unwrap();
    let private_key_bytes = hex::decode(params_struct.private_key).unwrap();
    let private_key = FennelRSAPrivateKey::from_u8(&private_key_bytes).unwrap();

    Ok(hex::encode(
        handle_decrypt(ciphertext, &private_key.pk).as_bytes(),
    ))
}

async fn rsa_sign(json: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Signing message...");
    let params_struct: types::SignPacket =
        serde_json::from_str(&json).expect("JSON was misformatted.");

    let message = params_struct.message.as_bytes();
    let private_key_bytes = hex::decode(params_struct.private_key).unwrap();
    let private_key = FennelRSAPrivateKey::from_u8(&private_key_bytes).unwrap();

    Ok(hex::encode(
        handle_sign(&String::from_utf8_lossy(message), private_key.pk).as_bytes(),
    ))
}

async fn rsa_verify(json: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Verifying message...");
    let params_struct: types::VerifyPacket =
        serde_json::from_str(&json).expect("JSON was misformatted.");

    let public_key_bytes: Vec<u8> = params_struct.public_key_bytes.into_bytes();
    let message: Vec<u8> = params_struct.message.into_bytes();
    let signature: Vec<u8> = params_struct.signature.into_bytes();

    let public_key = FennelRSAPublicKey::from_u8(&public_key_bytes).unwrap();
    Ok(warp::reply::json(&verify(
        &public_key.pk,
        message,
        signature,
    )))
}

async fn whiteflag_decode(hex: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Decoding message...");
    let result = whiteflag_rust::decode_from_hex(hex);
    let message = match result.is_ok() {
        true => types::WhiteflagDecodeResponse {
            success: true,
            decoded: Some(result.unwrap()),
            error: None,
        },
        false => types::WhiteflagDecodeResponse {
            success: false,
            decoded: None,
            error: Some(result.unwrap_err().to_string()),
        },
    };
    Ok(warp::reply::json(&message))
}

pub async fn start_api() {
    println!("Starting server on port 9031");

    let hello = warp::get()
        .and(warp::path("v1"))
        .and(warp::path("hello_there"))
        .and(warp::path::end())
        .and_then(hello_there);

    let post_test = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("post_test"))
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|_simple_map: HashMap<String, String>| "Got a JSON body!");

    let keypair = warp::get()
        .and(warp::path("v1"))
        .and(warp::path("get_or_generate_keypair"))
        .and(warp::path::end())
        .and_then(generate_keypair);

    let generate_encryption_channel = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("generate_encryption_channel"))
        .and(warp::path::end())
        .and_then(generate_encryption_channel);

    let accept_encryption_channel = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("accept_encryption_channel"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|json_map: HashMap<String, String>| {
            println!("Accepting encryption channel...");
            let json = hashmap_to_json_string(json_map);
            let params_struct: types::AcceptEncryptionChannelPacket =
                serde_json::from_str(&json).expect("JSON was misformatted.");
            let shared_secret =
                parse_shared_secret(params_struct.secret.to_string(), params_struct.public);
            let r = types::AcceptEncryptionChannelResponse {
                shared_secret: hex::encode(shared_secret.to_bytes()),
            };
            Ok(warp::reply::json(&r))
        });

    let dh_encrypt = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("dh_encrypt"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|json_map: HashMap<String, String>| {
            println!("Encrypting message...");
            let json = hashmap_to_json_string(json_map);
            let params_struct: types::DhEncryptPacket =
                serde_json::from_str(&json).expect("JSON was misformatted.");
            let shared_secret: [u8; 32] = hex::decode(params_struct.shared_secret)
                .unwrap()
                .try_into()
                .expect("Unable to match shared secret to a length of 32 bytes.");
            let cipher = prep_cipher_from_secret(&shared_secret);
            let ciphertext = handle_aes_encrypt(cipher, params_struct.plaintext);
            Ok(hex::encode(ciphertext))
        });

    let dh_decrypt = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("dh_decrypt"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|json_map: HashMap<String, String>| {
            println!("Decrypting message...");
            let json = hashmap_to_json_string(json_map);
            let params_struct: types::DhDecryptPacket =
                serde_json::from_str(&json).expect("JSON was misformatted.");
            let ciphertext_mod = match hex::decode(params_struct.ciphertext) {
                Ok(v) => v,
                Err(e) => panic!("Problem with decoding ciphertext: {}", e),
            };
            let shared_secret: [u8; 32] = hex::decode(params_struct.shared_secret)
                .unwrap()
                .try_into()
                .expect("Unable to match shared secret to a length of 32 bytes.");
            let cipher = prep_cipher_from_secret(&shared_secret);
            Ok(handle_aes_decrypt(cipher, ciphertext_mod))
        });

    let rsa_encrypt = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("rsa_encrypt"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and_then(rsa_encrypt);

    let rsa_decrypt = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("rsa_decrypt"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and_then(rsa_decrypt);

    let rsa_sign = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("rsa_sign"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and_then(rsa_sign);

    let rsa_verify = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("rsa_verify"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and_then(rsa_verify);

    let whiteflag_encode = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("whiteflag_encode"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|json_map: HashMap<String, String>| {
            let json = hashmap_to_json_string(json_map);
            println!("Encoding message...");
            let result = whiteflag_rust::encode_from_json(json);
            let response = match result {
                Ok(s) => types::WhiteflagEncodeResponse {
                    success: true,
                    encoded: Some(s),
                    error: None,
                },
                Err(e) => types::WhiteflagEncodeResponse {
                    success: false,
                    encoded: None,
                    error: Some(format!("{:?}", e)),
                },
            };
            Ok(warp::reply::json(&response))
        });

    let whiteflag_decode = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("whiteflag_decode"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .and_then(whiteflag_decode);

    let big_multiply = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("big_multiply"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json())
        .map(|json_map: HashMap<String, String>| {
            let json = hashmap_to_json_string(json_map);
            println!("Multiplying big numbers...");
            let params_struct: types::BigMultiplyPacket = match serde_json::from_str(&json) {
                Ok(s) => s,
                Err(e) => {
                    println!("Problem with deserializing JSON: {}", e);
                    types::BigMultiplyPacket { a: None, b: None }
                }
            };
            if params_struct.a.is_none() || params_struct.b.is_none() {
                return Ok(warp::reply::json(&BigMultiplyResponse {
                    success: false,
                    result: 0,
                    error: Some("Invalid input".to_string()),
                }));
            }
            let a = params_struct.a.unwrap().parse::<u128>().unwrap();
            let b = params_struct.b.unwrap().parse::<u128>().unwrap();
            let c: BigMultiplyResponse = match a.checked_mul(b) {
                Some(result) => BigMultiplyResponse {
                    success: true,
                    result,
                    error: None,
                },
                None => BigMultiplyResponse {
                    success: false,
                    result: 0,
                    error: Some("Overflow error".to_string()),
                },
            };
            Ok(warp::reply::json(&c))
        });

    let routes = hello
        .or(post_test)
        .or(keypair)
        .or(generate_encryption_channel)
        .or(accept_encryption_channel)
        .or(dh_encrypt)
        .or(dh_decrypt)
        .or(rsa_encrypt)
        .or(rsa_decrypt)
        .or(rsa_sign)
        .or(rsa_verify)
        .or(whiteflag_encode)
        .or(whiteflag_decode)
        .or(big_multiply);

    warp::serve(routes).run(([0, 0, 0, 0], 9031)).await;
}
