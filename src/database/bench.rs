use crate::database::*;
use std::sync::Arc;

use crate::get_identity_database_handle;

#[test]
fn test_insert_and_retrieve_message(b: &mut Bencher) {
    let db = get_message_database_handle();
    let db_2 = Arc::clone(&db);
    b.iter(|| {
        insert_message(
            db,
            Message {
                sender_id: [0; 32],
                fingerprint: [0; 32],
                message: [0; 1024],
                signature: [0; 1024],
                public_key: [0; 1038],
                recipient_id: [0; 32],
            },
        )
        .expect("failed message insertion");
        let result: Vec<Message> = retrieve_messages(
            db_2,
            Identity {
                id: [0; 32],
                fingerprint: [0; 32],
                public_key: [0; 1038],
            },
        );
    });
}

#[test]
fn test_insert_and_retrieve_identity(b: &mut Bencher) {
    let db = get_identity_database_handle();
    let db_2 = Arc::clone(&db);
    let identity: Identity = Identity {
        id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    b.iter(|| {
        insert_identity(db, &identity).expect("failed identity insertion");
        let result: Identity = retrieve_identity(db_2, [0; 32]);
    });
}
