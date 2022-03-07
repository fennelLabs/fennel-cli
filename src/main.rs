#![feature(test)]

mod client;
mod command;
use std::{error::Error, sync::Arc};

use clap::Parser;
use client::{
    handle_aes_encrypt, handle_backlog_decrypt, handle_connection, handle_decrypt,
    handle_diffie_hellman_one, handle_diffie_hellman_two, handle_encrypt, handle_generate_keypair,
    handle_sign, handle_verify,
};
use command::{Cli, Commands};
use fennel_lib::{
    export_public_key_to_binary, get_identity_database_handle, get_message_database_handle,
    insert_identity, retrieve_identity, sign, FennelServerPacket, Identity,
};
use tokio::net::TcpStream;

use crate::client::{handle_aes_decrypt, prep_cipher};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let identity_db = get_identity_database_handle();
    let message_db = get_message_database_handle();

    let (fingerprint, private_key, public_key) = handle_generate_keypair();

    match &args.command {
        Commands::Encrypt {
            identity,
            plaintext,
        } => {
            println!(
                "{}",
                hex::encode(handle_encrypt(identity_db, identity, plaintext))
            );
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
        Commands::AcceptEncryptionChannel {
            identity_id,
            secret_key,
            public_key,
        } => {
            let shared_secret =
                handle_diffie_hellman_two(secret_key.to_string(), public_key.to_string());
            let mut identity = retrieve_identity(identity_db.clone(), identity_id.to_ne_bytes());
            identity.shared_secret_key = shared_secret.to_bytes();
            insert_identity(identity_db, &identity).unwrap();
            println!("Encryption channel ready");
        }
        Commands::SendSecureMessage {} => {}
        Commands::ReceiveSecureMessages {} => {}

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

        Commands::Sign { message } => println!("{}", handle_sign(message, private_key)),
        Commands::Verify {
            message,
            signature,
            identity,
        } => println!(
            "Verified: {}",
            handle_verify(identity_db, message, signature, identity)
        ),

        Commands::DecryptBacklog { identity } => handle_backlog_decrypt(
            message_db,
            identity_db,
            Identity {
                id: identity.to_ne_bytes(),
                fingerprint,
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                shared_secret_key: [0; 32],
            },
            private_key,
        ),

        Commands::CreateIdentity { id } => {
            let packet = FennelServerPacket {
                command: [0; 1],
                identity: id.to_ne_bytes(),
                fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
            handle_connection(identity_db, message_db, listener, packet).await?
        }
        Commands::SendMessage {
            sender_id,
            message,
            recipient_id,
        } => {
            let identity_db_2 = Arc::clone(&identity_db);
            let ciphertext = handle_encrypt(identity_db, recipient_id, message);
            let packet = FennelServerPacket {
                command: [1; 1],
                identity: sender_id.to_ne_bytes(),
                fingerprint,
                message: ciphertext.to_owned().try_into().unwrap(),
                signature: sign(private_key, ciphertext).to_vec().try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: recipient_id.to_ne_bytes(),
            };
            let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
            handle_connection(identity_db_2, message_db, listener, packet).await?
        }
        Commands::GetMessages { id } => {
            let packet = FennelServerPacket {
                command: [2; 1],
                identity: id.to_ne_bytes(),
                fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
            handle_connection(identity_db, message_db, listener, packet).await?
        }
        Commands::RetrieveIdentity { id } => {
            let packet = FennelServerPacket {
                command: [3; 1],
                identity: id.to_ne_bytes(),
                fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
            handle_connection(identity_db, message_db, listener, packet).await?
        }
    }

    Ok(())
}
