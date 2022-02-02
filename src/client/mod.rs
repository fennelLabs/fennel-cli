#[cfg(test)]
mod tests;

use crate::database::insert_identity;
use crate::database::insert_message;
use crate::database::insert_message_list;
use crate::database::Identity;
use crate::database::Message;
use crate::import_public_key_from_binary;
use crate::verify;
use codec::Decode;
use codec::Encode;
use rocksdb::DB;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::io::*;
use tokio::net::TcpStream;

#[derive(Copy, Clone, Encode, Decode)]
struct FennelServerPacket {
    command: [u8; 1],
    identity: [u8; 32],
    fingerprint: [u8; 32],
    message: [u8; 1024],
    signature: [u8; 1024],
    public_key: [u8; 1038],
    recipient: [u8; 32],
}

pub async fn handle_connection(
    identity_db: Arc<Mutex<DB>>,
    message_db: Arc<Mutex<DB>>,
    mut stream: TcpStream,
) -> Result<()> {
    let mut buffer = [0; 3184];
    stream.read_exact(&mut buffer).await.unwrap();
    let server_packet: FennelServerPacket = FennelServerPacket {
        command: [0; 1],
        identity: [0; 32],
        fingerprint: [0; 32],
        message: [0; 1024],
        signature: [0; 1024],
        public_key: [0; 1038],
        recipient: [0; 32],
    };
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
        let messages_list = parse_remote_messages(identity_db, response, server_packet).await;
        put_messages(message_db, messages_list)
            .await
            .expect("failed to commit messages");
    } else {
        stream.write_all(&[0]).await?;
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

async fn parse_remote_messages(
    identity_database: Arc<Mutex<DB>>,
    messages_response: Vec<[u8; 3182]>,
    packet: FennelServerPacket,
) -> Vec<Message> {
    let mut message_list: Vec<Message> = Vec::new();
    for message in messages_response {
        message_list.push(Decode::decode(&mut (message.as_slice())).unwrap());
    }
    message_list
}

async fn put_messages(messages_db: Arc<Mutex<DB>>, messages_list: Vec<Message>) -> Result<()> {
    insert_message_list(messages_db, messages_list).unwrap();
    Ok(())
}
