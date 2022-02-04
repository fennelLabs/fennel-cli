#![feature(test)]

mod client;
mod command;
use std::error::Error;

use clap::Parser;
use client::{
    handle_connection, handle_decrypt, handle_encrypt, handle_generate_keypair, handle_sign,
    handle_verify,
};
use codec::Encode;
use command::{Cli, Commands};
use fennel_lib::{get_identity_database_handle, get_message_database_handle, FennelServerPacket, export_public_key_to_binary, sign};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let listener: TcpStream = TcpStream::connect("127.0.0.1:7878").await?;
    let identity_db = get_identity_database_handle();
    let message_db = get_message_database_handle();

    let (fingerprint, private_key, public_key) = handle_generate_keypair();

    match &args.command {
        Commands::Encrypt {
            identity,
            plaintext,
        } => {
            handle_encrypt(identity_db, identity, plaintext);
        }
        Commands::Decrypt { ciphertext } => handle_decrypt(ciphertext, private_key),

        Commands::Sign { message } => handle_sign(message, private_key),
        Commands::Verify {
            message,
            signature,
            identity,
        } => handle_verify(identity_db, message, signature, identity),

        Commands::SendMessage {
            sender_id,
            message,
            recipient_id,
        } => {
            let packet = FennelServerPacket {
                command: [1; 1],
                identity: sender_id.to_ne_bytes(),
                fingerprint: fingerprint,
                message: message.encode().try_into().unwrap(),
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: recipient_id.to_ne_bytes(),
            };
            handle_connection(identity_db, message_db, listener, packet).await?
        }
        Commands::GetMessages { id } => {
            let packet = FennelServerPacket {
                command: [2; 1],
                identity: id.to_ne_bytes(),
                fingerprint: fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            handle_connection(identity_db, message_db, listener, packet).await?
        }

        Commands::CreateIdentity {
            id
        } => {
            let packet = FennelServerPacket {
                command: [0; 1],
                identity: id.to_ne_bytes(),
                fingerprint: fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            handle_connection(identity_db, message_db, listener, packet).await?
        }
        Commands::RetrieveIdentity { id } => {
            let packet = FennelServerPacket {
                command: [0; 1],
                identity: id.to_ne_bytes(),
                fingerprint: fingerprint,
                message: [0; 1024],
                signature: sign(private_key, [0; 1024].to_vec()).try_into().unwrap(),
                public_key: export_public_key_to_binary(&public_key).unwrap(),
                recipient: [0; 4],
            };
            handle_connection(identity_db, message_db, listener, packet).await?
        }
    }

    Ok(())
}
