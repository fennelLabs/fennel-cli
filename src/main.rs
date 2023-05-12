#![allow(deprecated)]

mod client;
mod command;
mod fennel_rpc;
use clap::Parser;
use client::{
    handle_aes_encrypt, handle_decrypt, handle_diffie_hellman_one, handle_encrypt,
    handle_generate_keypair, handle_sign, handle_verify,
};
use command::{Cli, Commands};
use fennel_lib::FennelRSAPublicKey;
use rsa::RsaPublicKey;
use std::error::Error;

use crate::client::{handle_aes_decrypt, prep_cipher};
use crate::fennel_rpc::start_rpc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let (_fingerprint, private_key, public_key) = handle_generate_keypair(4096);
    let pk = FennelRSAPublicKey::new(public_key).unwrap();

    match &args.command {
        Commands::Encrypt {
            public_key,
            plaintext,
        } => {
            println!("{}", hex::encode(handle_encrypt(public_key, plaintext)));
        }
        Commands::Decrypt { ciphertext } => {
            println!(
                "{}",
                handle_decrypt(hex::decode(ciphertext).unwrap(), &private_key)
            )
        }

        Commands::GenerateEncryptionChannel {} => {
            let (secret, public) = handle_diffie_hellman_one();
            println!(
                "Secret key (KEEP THIS SAFE): {}",
                hex::encode(secret.to_bytes())
            );
            println!(
                "Public key (SHARE THIS): {}",
                hex::encode(public.as_bytes())
            );
        }
        Commands::AESEncrypt {
            secret,
            public_key,
            plaintext,
        } => {
            let cipher = prep_cipher(secret.to_string(), public_key.to_string());
            println!(
                "{}",
                hex::encode(handle_aes_encrypt(cipher, plaintext.to_string()))
            );
        }
        Commands::AESDecrypt {
            secret,
            public_key,
            ciphertext,
        } => {
            let cipher = prep_cipher(secret.to_string(), public_key.to_string());
            println!(
                "{}",
                handle_aes_decrypt(cipher, hex::decode(ciphertext).unwrap())
            );
        }

        Commands::ShowPublicKey {} => {
            println!("{}", hex::encode(pk.as_u8()));
        }

        Commands::Sign { message } => println!("{}", handle_sign(message, private_key)),
        Commands::Verify {
            message,
            signature,
            public_key,
        } => println!(
            "Verified: {}",
            handle_verify(message, signature, public_key)
        ),

        Commands::StartRPC {} => {
            println!("Starting RPC on localhost:9030");
            start_rpc().await?;
        }
    }

    Ok(())
}

fn convert_to_sized_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn convert_rsa(pk: RsaPublicKey) -> [u8; 526] {
    convert_to_sized_array(FennelRSAPublicKey::new(pk).unwrap().as_u8().to_vec())
}
