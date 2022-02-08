use std::sync::Arc;

use fennel_lib::{
    export_public_key_to_binary, get_identity_database_handle, insert_identity, Identity,
};

use crate::client::{handle_sign, handle_verify};

use super::{handle_decrypt, handle_encrypt, handle_generate_keypair};

#[test]
/// Tests the processes for generating keys, encrypting text, and decrypting the resulting ciphertext.
fn test_handle_encrypt_and_decrypt() {
    let db = get_identity_database_handle();
    let db_2 = Arc::clone(&db);
    let db_3 = Arc::clone(&db_2);
    let db_4 = Arc::clone(&db_2);

    let (_, private_key, public_key) = handle_generate_keypair();
    let key_bytes = export_public_key_to_binary(&public_key).expect("failed to decode public key");

    let identity: Identity = Identity {
        id: [0; 4],
        fingerprint: [0; 16],
        public_key: key_bytes,
    };
    insert_identity(db, &identity).expect("failed identity insertion");

    let result = handle_encrypt(db_2, &0, &String::from("test"));
    let decrypted = handle_decrypt(&result, private_key);

    assert_eq!(String::from("test"), decrypted);

    let (_, private_key, public_key) = handle_generate_keypair();
    let key_bytes = export_public_key_to_binary(&public_key).expect("failed to decode public key");

    let identity: Identity = Identity {
        id: [0; 4],
        fingerprint: [0; 16],
        public_key: key_bytes,
    };
    insert_identity(db_3, &identity).expect("failed identity insertion");

    let signature = handle_sign(&String::from("Test"), private_key);
    assert_eq!(
        handle_verify(db_4, &String::from("Test"), &signature, &0),
        true
    )
}
