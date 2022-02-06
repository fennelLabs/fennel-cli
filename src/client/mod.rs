#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use fennel_lib::{
    export_public_key_to_binary, generate_keypair, hash, import_keypair_from_file,
    import_public_key_from_binary, insert_identity, insert_message, retrieve_identity,
    retrieve_messages,
    rsa_tools::{decrypt, encrypt},
    sign, verify, FennelServerPacket, Identity, Message,
};
use rocksdb::DB;
use rsa::RsaPrivateKey;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{io::*, net::TcpStream};

pub async fn handle_connection(
    identity_db: Arc<Mutex<DB>>,
    message_db: Arc<Mutex<DB>>,
    mut stream: TcpStream,
    server_packet: FennelServerPacket,
) -> Result<()> {
    let mut server_response_code = [0; 1];
    if server_packet.command == [0] {
        let r = submit_identity(identity_db, server_packet).await;
        if r == &[0] {
            panic!("identity failed to commit.");
        }
        stream.write_all(&server_packet.encode()).await?;
        stream.read_exact(&mut server_response_code).await?;
        if &server_response_code != &[0] {
            panic!("server operation failed")
        }
    } else if server_packet.command == [1] {
        let r = send_message(message_db, server_packet).await;
        if r == &[0] {
            panic!("identity failed to commit.");
        }
        stream.write_all(&server_packet.encode()).await?;
        stream.read_exact(&mut server_response_code).await?;
        if &server_response_code != &[0] {
            panic!("server operation failed")
        }
    } else if server_packet.command == [2] {
        stream.write_all(&server_packet.encode()).await?;
        let mut response: Vec<[u8; 3182]> = Vec::new();
        let mut end = [1];
        if end != [0] {
            let mut message_buffer = [0; 3182];
            stream.read_exact(&mut message_buffer).await?;
            response.push(message_buffer);
            stream.read_exact(&mut end).await?;
        }
        put_messages(message_db, parse_remote_messages(response).await)
            .await
            .expect("failed to commit messages");
    } else {
        stream.write_all(&[0]).await?;
    }

    Ok(())
}

async fn submit_identity(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    let r = insert_identity(
        db,
        &(Identity {
            id: packet.identity,
            fingerprint: packet.fingerprint,
            public_key: packet.public_key,
        }),
    );
    match r {
        Ok(_) => &[0],
        Err(_) => &[1],
    }
}

async fn send_message(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    let r = insert_message(
        db,
        Message {
            sender_id: packet.identity,
            fingerprint: packet.fingerprint,
            message: packet.message,
            signature: packet.signature,
            public_key: packet.public_key,
            recipient_id: packet.recipient,
        },
    );
    match r {
        Ok(_) => &[0],
        Err(_) => &[1],
    }
}

async fn parse_remote_messages(messages_response: Vec<[u8; 3182]>) -> Vec<Message> {
    let mut message_list: Vec<Message> = Vec::new();
    for message in messages_response {
        let unpacked_message = Decode::decode(&mut (message.as_slice())).unwrap();
        message_list.push(unpacked_message);
    }
    message_list
}

async fn put_messages(messages_db: Arc<Mutex<DB>>, messages_list: Vec<Message>) -> Result<()> {
    insert_message_list(messages_db, messages_list).unwrap();
    Ok(())
}

fn insert_message_list(messages_db: Arc<Mutex<DB>>, messages_list: Vec<Message>) -> Result<()> {
    for message in messages_list {
        let messages_db_clone = Arc::clone(&messages_db);
        insert_message(messages_db_clone, message).unwrap();
    }
    Ok(())
}

pub fn handle_backlog_decrypt(
    message_db: Arc<Mutex<DB>>,
    identity_db: Arc<Mutex<DB>>,
    identity: Identity,
    private_key: RsaPrivateKey,
) {
    let message_list = retrieve_messages(message_db, identity);
    for message in message_list {
        let sender_identity = retrieve_identity(Arc::clone(&identity_db), message.sender_id);
        println!(
            "{:?} Verified: {:?}",
            message.sender_id,
            verify(
                import_public_key_from_binary(&sender_identity.public_key).unwrap(),
                message.message.to_vec(),
                message.signature.to_vec()
            )
        );
        println!("{:?}", decrypt(&private_key, message.message.to_vec()));
        println!();
    }
}

pub fn handle_generate_keypair() -> ([u8; 16], rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let (private_key, public_key): (rsa::RsaPrivateKey, rsa::RsaPublicKey) =
        match import_keypair_from_file(
            PathBuf::from("./Private.key"),
            PathBuf::from("./Public.key"),
        ) {
            Ok(v) => v,
            Err(_) => generate_keypair(8192),
        };
    let fingerprint: [u8; 16] = hash(export_public_key_to_binary(&public_key).unwrap())[0..16]
        .try_into()
        .unwrap();
    (fingerprint, private_key, public_key)
}

pub fn handle_encrypt(db_lock: Arc<Mutex<DB>>, identity: &u32, plaintext: &String) {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let public_key = import_public_key_from_binary(&recipient.public_key).unwrap();
    let ciphertext = encrypt(public_key, plaintext.as_bytes().to_vec());
    println!("{}", std::str::from_utf8(&ciphertext).unwrap());
}

pub fn handle_decrypt(ciphertext: &String, private_key: rsa::RsaPrivateKey) {
    let plaintext = decrypt(&private_key, ciphertext.as_bytes().to_vec());
    println!("{}", std::str::from_utf8(&plaintext).unwrap());
}

pub fn handle_sign(message: &String, private_key: rsa::RsaPrivateKey) {
    let signature = sign(private_key, message.as_bytes().to_vec());
    println!("{}", std::str::from_utf8(&signature).unwrap());
}

pub fn handle_verify(
    db_lock: Arc<Mutex<DB>>,
    message: &String,
    signature: &String,
    identity: &u32,
) {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let public_key = import_public_key_from_binary(&recipient.public_key).unwrap();
    if verify(
        public_key,
        message.as_bytes().to_vec(),
        signature.as_bytes().to_vec(),
    ) {
        println!("Verified: {}", identity);
    } else {
        println!("Signature failed to verify.");
    }
}
