use std::sync::Arc;

use fennel_lib::{
    get_identity_database_handle, get_message_database_handle, insert_identity, insert_message,
    retrieve_identity, retrieve_messages, sign, verify, Identity, Message,
};

use crate::{
    client::{
        handle_diffie_hellman_decrypt, handle_diffie_hellman_encrypt, handle_sign, handle_verify,
        parse_shared_secret, prep_cipher,
    },
    convert_rsa,
};

use super::{
    handle_aes_decrypt, handle_aes_encrypt, handle_backlog_decrypt, handle_decrypt,
    handle_diffie_hellman_one, handle_encrypt, handle_generate_keypair, pack_message,
    unpack_message,
};

#[test]
/// Tests the processes for generating keys, encrypting text, and decrypting the resulting ciphertext.
fn test_handle_encrypt_and_decrypt() {
    let (_, private_key, public_key) = handle_generate_keypair();
    let key_bytes = convert_rsa(public_key);

    let result = handle_encrypt(&hex::encode(key_bytes), &String::from("test"));
    let decrypted = handle_decrypt(result, &private_key);

    assert_eq!(String::from("test"), decrypted);
}

#[test]
fn test_handle_sign_and_verify() {
    let (_, private_key, public_key) = handle_generate_keypair();
    let key_bytes = convert_rsa(public_key);

    let signature = handle_sign(&String::from("Test"), private_key);
    assert_eq!(
        handle_verify(&String::from("Test"), &signature, &hex::encode(key_bytes)),
        true
    )
}

#[test]
fn test_handle_backlog_decrypt() {
    let identity_db = get_identity_database_handle();
    let identity_db_clone = Arc::clone(&identity_db);
    let identity_db_2 = Arc::clone(&identity_db);
    let identity_db_3 = Arc::clone(&identity_db);
    let message_db = get_message_database_handle();
    let message_db_clone = Arc::clone(&message_db);
    let message_db_2 = Arc::clone(&message_db);

    let (fingerprint, private_key, public_key) = handle_generate_keypair();
    let (_, private_key_loaded, public_key_loaded) = handle_generate_keypair();
    assert_eq!(&private_key, &private_key_loaded);

    let pk_526 = convert_rsa(public_key);

    let identity = Identity {
        id: [9, 0, 0, 0],
        fingerprint,
        public_key: pk_526.clone(),
        shared_secret_key: [0; 32],
    };

    insert_identity(identity_db_clone, &identity).expect("failed to insert identity");

    let ciphertext_verify = handle_encrypt(&hex::encode(pk_526), &String::from("This is a test"));
    assert_eq!(
        handle_decrypt(ciphertext_verify, &private_key),
        String::from("This is a test")
    );
    let ciphertext = handle_encrypt(&hex::encode(pk_526), &String::from("This is a test"));
    let ciphertext_array = ciphertext.to_owned();
    let ciphertext_sign = ciphertext.to_owned();

    let message = Message {
        sender_id: [9, 0, 0, 0],
        fingerprint,
        message: ciphertext_array.try_into().unwrap(),
        signature: sign(&private_key, ciphertext_sign.try_into().unwrap())
            .to_vec()
            .try_into()
            .unwrap(),
        public_key: pk_526.clone(),
        recipient_id: [9, 0, 0, 0],
        message_type: [0],
    };

    insert_message(message_db, message).expect("failed to insert message");

    let received_identity = retrieve_identity(identity_db_3, [9, 0, 0, 0]);
    assert_eq!(identity.fingerprint, received_identity.fingerprint);

    let messages = retrieve_messages(message_db_2, identity);
    let encoded_ciphertext: [u8; 512] = ciphertext.try_into().unwrap();
    assert!(verify(
        &public_key_loaded,
        messages[0].message.to_vec(),
        messages[0].signature.to_vec()
    ));
    assert_eq!(messages[0].message, encoded_ciphertext);

    let identity_copy = Identity {
        id: [9, 0, 0, 0],
        fingerprint: fingerprint,
        public_key: pk_526.clone(),
        shared_secret_key: [0; 32],
    };

    handle_backlog_decrypt(
        message_db_clone,
        identity_db_2,
        identity_copy,
        private_key_loaded,
    );
}

#[test]
fn test_diffie_hellman() {
    let (secret_key, public_key) = handle_diffie_hellman_one();
    let secret = hex::encode(secret_key.to_bytes());
    let public = hex::encode(public_key.to_bytes());
    let shared1 = parse_shared_secret(secret.clone(), public.clone());
    let shared2 = parse_shared_secret(secret.clone(), public.clone());
    assert_eq!(shared1.as_bytes(), shared2.as_bytes());

    let cipher = prep_cipher(secret.clone(), public.clone());
    let ciphertext = handle_aes_encrypt(cipher, String::from("This is a test."));
    let ciphertext_hex = hex::encode(ciphertext);

    let cipher = prep_cipher(secret, public);
    let plaintext = handle_aes_decrypt(cipher, hex::decode(ciphertext_hex).unwrap());

    assert_eq!(String::from("This is a test."), plaintext);
}

#[test]
fn test_handle_backlog_decrypt_with_dh() {
    let identity_db = get_identity_database_handle();
    let identity_db_clone = Arc::clone(&identity_db);
    let identity_db_2 = Arc::clone(&identity_db);
    let identity_db_3 = Arc::clone(&identity_db);
    let identity_db_4 = Arc::clone(&identity_db);
    let message_db = get_message_database_handle();
    let message_db_clone = Arc::clone(&message_db);
    let message_db_2 = Arc::clone(&message_db);

    let (secret_key, public_key) = handle_diffie_hellman_one();
    let secret = hex::encode(secret_key.to_bytes());
    let public = hex::encode(public_key.to_bytes());
    let shared1 = parse_shared_secret(secret.clone(), public.clone());

    let (fingerprint, private_key, public_key) = handle_generate_keypair();
    let (_, private_key_loaded, public_key_loaded) = handle_generate_keypair();
    assert_eq!(&private_key, &private_key_loaded);

    let pk_526 = convert_rsa(public_key);

    let identity = Identity {
        id: [8, 0, 0, 0],
        fingerprint,
        public_key: pk_526.clone(),
        shared_secret_key: shared1.to_bytes(),
    };

    insert_identity(identity_db_clone, &identity).expect("failed to insert identity");

    let ciphertext_verify = handle_diffie_hellman_encrypt(
        Arc::clone(&identity_db),
        &8,
        &String::from("This is a test"),
    );
    assert_eq!(
        handle_diffie_hellman_decrypt(Arc::clone(&identity_db), [8, 0, 0, 0], ciphertext_verify),
        String::from("This is a test")
    );
    let ciphertext =
        handle_diffie_hellman_encrypt(identity_db_4, &8, &String::from("This is a test"));
    let ciphertext_array = ciphertext.to_owned();
    let ciphertext_sign = ciphertext.to_owned();
    println!("{:?}", ciphertext_array.len());

    let message = Message {
        sender_id: [8, 0, 0, 0],
        fingerprint,
        message: ciphertext_array.try_into().unwrap(),
        signature: sign(&private_key, ciphertext_sign.try_into().unwrap())
            .to_vec()
            .try_into()
            .unwrap(),
        public_key: pk_526.clone(),
        recipient_id: [8, 0, 0, 0],
        message_type: [2],
    };

    insert_message(message_db, message).expect("failed to insert message");

    let received_identity = retrieve_identity(identity_db_3, [8, 0, 0, 0]);
    assert_eq!(identity.fingerprint, received_identity.fingerprint);

    let messages = retrieve_messages(message_db_2, identity);
    let encoded_ciphertext: [u8; 512] = ciphertext.try_into().unwrap();
    assert!(verify(
        &public_key_loaded,
        messages[0].message.to_vec(),
        messages[0].signature.to_vec()
    ));
    assert_eq!(messages[0].message, encoded_ciphertext);

    let identity_copy = Identity {
        id: [8, 0, 0, 0],
        fingerprint: fingerprint,
        public_key: pk_526.clone(),
        shared_secret_key: [0; 32],
    };

    handle_backlog_decrypt(
        message_db_clone,
        identity_db_2,
        identity_copy,
        private_key_loaded,
    );
}

#[test]
fn test_pack_message() {
    let test = vec![1, 2, 3, 4, 5];
    let packed_test = pack_message(test);
    assert_eq!(packed_test.len(), 512);
    assert_eq!(packed_test[0], 5);
}

#[test]
fn test_unpack_message() {
    let test = vec![1, 2, 3, 4, 5];
    let packed_test = pack_message(test.clone());
    let unpacked_test = unpack_message(packed_test.clone());
    assert_eq!(test, unpacked_test);
}
