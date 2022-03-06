#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use fennel_lib::{
    aes_decrypt, aes_encrypt, export_keypair_to_file, export_public_key_to_binary,
    generate_keypair, get_session_public_key, get_session_secret, get_shared_secret, hash,
    import_keypair_from_file, import_public_key_from_binary, insert_identity, insert_message,
    retrieve_identity, retrieve_messages,
    rsa_tools::{decrypt, encrypt},
    sign, verify, AESCipher, FennelServerPacket, Identity, Message,
};
use rocksdb::DB;
use rsa::RsaPrivateKey;
use std::panic;
use std::str;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{io::*, net::TcpStream};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub async fn handle_connection(
    identity_db: Arc<Mutex<DB>>,
    message_db: Arc<Mutex<DB>>,
    mut stream: TcpStream,
    server_packet: FennelServerPacket,
) -> Result<()> {
    let mut server_response_code = [99; 1];
    if !verify_packet_signature(&server_packet) {
        panic!("server packet signature failed to verify");
    }
    if server_packet.command == [0] {
        let r = submit_identity(identity_db, server_packet).await;
        if r != [0] {
            panic!("identity failed to commit.");
        }
        stream.write_all(&server_packet.encode()).await?;
        println!("sent");
        stream.read_exact(&mut server_response_code).await?;
    } else if server_packet.command == [1] {
        let r = send_message(message_db, server_packet).await;
        if r != [0] {
            panic!("message failed to commit.");
        }
        stream.write_all(&server_packet.encode()).await?;
        println!("sent");
        stream.read_exact(&mut server_response_code).await?;
    } else if server_packet.command == [2] {
        stream.write_all(&server_packet.encode()).await?;
        println!("sent");
        let mut response: Vec<[u8; 3110]> = Vec::new();
        let mut end = [255];
        stream.read_exact(&mut end).await?;
        while end != [0] {
            println!("{} messages remaining", end[0]);
            let mut message_buffer = [0; 3110];
            let mut server_hash = [0; 64];
            let mut intermediate_response_code = [0; 1];
            stream.read_exact(&mut end).await?;
            stream.read_exact(&mut server_hash).await?;
            stream.read_exact(&mut message_buffer).await?;
            let client_hash: [u8; 64] = hash(&message_buffer).try_into().unwrap();
            stream.write_all(&client_hash).await?;
            if server_hash == client_hash {
                response.push(message_buffer);
            } else {
                println!("a message failed hash checking on our end.");
            }
            stream.read_exact(&mut intermediate_response_code).await?;
            if intermediate_response_code != [0] {
                println!("a message failed hash checking on the server end");
            }
        }
        stream.read_exact(&mut server_response_code).await?;
        put_messages(message_db, parse_remote_messages(response).await)
            .await
            .expect("failed to commit messages");
    } else {
        println!("invalid command code");
    }

    if server_response_code == [0] {
        println!("operation completed successfully");
    } else if server_response_code == [9] {
        println!("packet signature failed to verify");
    } else if server_response_code == [97] {
        println!("messages downloaded successfully");
    } else if server_response_code == [99] {
        println!("no server action taken");
    } else {
        println!("return code was: {:?}", &server_response_code);
        panic!("server operation failed");
    }

    Ok(())
}

fn verify_packet_signature(packet: &FennelServerPacket) -> bool {
    let pub_key =
        import_public_key_from_binary(&packet.public_key).expect("public key failed to import");
    verify(pub_key, packet.message.to_vec(), packet.signature.to_vec())
}

async fn submit_identity(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    let r = insert_identity(
        db,
        &(Identity {
            id: packet.identity,
            fingerprint: packet.fingerprint,
            public_key: packet.public_key,
            shared_secret_key: [0; 32],
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

async fn parse_remote_messages(messages_response: Vec<[u8; 3110]>) -> Vec<Message> {
    let mut message_list: Vec<Message> = Vec::new();
    for message in messages_response {
        let unpacked_message: Message = Decode::decode(&mut (message.as_slice())).unwrap();
        if verify(
            import_public_key_from_binary(&unpacked_message.public_key).unwrap(),
            unpacked_message.message.to_vec(),
            unpacked_message.signature.to_vec(),
        ) {
            message_list.push(unpacked_message);
        }
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
            "From: {:?} Verified: {:?}",
            u32::from_ne_bytes(message.sender_id),
            verify(
                import_public_key_from_binary(&sender_identity.public_key).unwrap(),
                message.message.to_vec(),
                message.signature.to_vec()
            )
        );
        println!(
            "{:?}",
            handle_decrypt(message.message.to_vec(), &private_key)
        );
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
            Err(_) => {
                println!("Setting up a new keypair...");
                let (private_key, public_key) = generate_keypair(8192);
                println!("Finished.");

                export_keypair_to_file(
                    &private_key,
                    &public_key,
                    PathBuf::from("./Private.key"),
                    PathBuf::from("./Public.key"),
                )
                .expect("failed to export keypair");

                (private_key, public_key)
            }
        };
    let fingerprint: [u8; 16] = hash(export_public_key_to_binary(&public_key).unwrap())[0..16]
        .try_into()
        .unwrap();
    (fingerprint, private_key, public_key)
}

pub fn handle_encrypt(db_lock: Arc<Mutex<DB>>, identity: &u32, plaintext: &str) -> Vec<u8> {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let public_key = import_public_key_from_binary(&recipient.public_key).unwrap();
    encrypt(public_key, plaintext.as_bytes().to_vec())
}

pub fn handle_decrypt(ciphertext: Vec<u8>, private_key: &rsa::RsaPrivateKey) -> String {
    let decrypted = decrypt(private_key, ciphertext);
    String::from(str::from_utf8(&decrypted).unwrap())
}

pub fn handle_sign(message: &str, private_key: rsa::RsaPrivateKey) -> String {
    hex::encode(sign(private_key, message.as_bytes().to_vec()))
}

pub fn handle_verify(
    db_lock: Arc<Mutex<DB>>,
    message: &str,
    signature: &str,
    identity: &u32,
) -> bool {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let public_key = import_public_key_from_binary(&recipient.public_key).unwrap();
    verify(
        public_key,
        message.as_bytes().to_vec(),
        hex::decode::<&String>(&String::from(signature)).unwrap(),
    )
}

fn parse_shared_secret(secret: String, public_key: String) -> SharedSecret {
    let secret_key_bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
    let parsed_secret_key = StaticSecret::from(secret_key_bytes);
    let key_bytes: [u8; 32] = hex::decode(public_key).unwrap().try_into().unwrap();
    let parsed_public_key = PublicKey::from(key_bytes);
    get_shared_secret(parsed_secret_key, &parsed_public_key)
}

pub fn prep_cipher(secret: String, public_key: String) -> AESCipher {
    let shared_secret = parse_shared_secret(secret, public_key);
    prep_cipher_from_secret(shared_secret.as_bytes())
}

pub fn prep_cipher_from_secret(shared_secret: &[u8; 32]) -> AESCipher {
    AESCipher::new_from_shared_secret(shared_secret)
}

pub fn handle_aes_encrypt(cipher: AESCipher, plaintext: String) -> Vec<u8> {
    aes_encrypt(&cipher.encrypt_key, cipher.iv, plaintext)
}

pub fn handle_aes_decrypt(cipher: AESCipher, ciphertext: Vec<u8>) -> String {
    aes_decrypt(&cipher.decrypt_key, cipher.iv, ciphertext)
}

pub fn handle_diffie_hellman_one() -> (StaticSecret, PublicKey) {
    let secret = get_session_secret();
    let public = get_session_public_key(&secret);
    (secret, public)
}

pub fn handle_diffie_hellman_two(secret: String, public_key: String) -> SharedSecret {
    parse_shared_secret(secret, public_key)
}

pub fn handle_diffie_hellman_encrypt(db_lock: Arc<Mutex<DB>>, identity: &u32, plaintext: &str) -> Vec<u8> {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let cipher = prep_cipher_from_secret(&recipient.shared_secret_key);
    handle_aes_encrypt(cipher, plaintext.to_string())
}

pub fn handle_diffie_hellman_decrypt(db_lock: Arc<Mutex<DB>>, identity: &u32, ciphertext: Vec<u8>) -> String {
    let id_array = identity.to_ne_bytes();
    let recipient = retrieve_identity(db_lock, id_array);
    let cipher = prep_cipher_from_secret(&recipient.shared_secret_key);
    handle_aes_decrypt(cipher, ciphertext)
}
