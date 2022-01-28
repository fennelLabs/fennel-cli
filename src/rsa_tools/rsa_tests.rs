#[cfg(test)]
mod rsa_tests {
    use super::super::rsa_tools::*;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use std::path::PathBuf;

    #[test]
    fn test_generate() {
        generate_keypair(2048);
    }

    #[test]
    fn test_export() {
        let (private_key, public_key) = generate_keypair(2048);
        export_keypair_to_file(
            &private_key,
            &public_key,
            PathBuf::from("./Private.key"),
            PathBuf::from("./Public.key"),
        )
        .expect("failed to export keys");
    }

    #[test]
    fn test_import() {
        let (private_key, public_key) = generate_keypair(2048);
        export_keypair_to_file(
            &private_key,
            &public_key,
            PathBuf::from("./Private.key"),
            PathBuf::from("./Public.key"),
        )
        .expect("failed to export keys");
        let (new_private_key, new_public_key) = import_keypair_from_file(
            PathBuf::from("./Private.key"),
            PathBuf::from("./Public.key"),
        )
        .expect("failed to import key");
        assert_eq!(&private_key, &new_private_key);
        assert_eq!(&public_key, &new_public_key);
    }

    #[test]
    fn test_encrypt() {
        let test = b"this is test text";
        let (_, public_key) = generate_keypair(2048);
        encrypt(public_key, test.to_vec());
    }

    #[test]
    fn test_decrypt() {
        let test = b"this is test text";
        let (private_key, public_key) = generate_keypair(2048);
        let result = encrypt(public_key, test.to_vec());
        let decrypt_result = decrypt(private_key, result);
        assert_eq!(test.to_vec(), decrypt_result);
    }

    #[test]
    fn test_sign() {
        let test = b"this is test text";
        let (private_key, _) = generate_keypair(2048);
        sign(private_key, test.to_vec());
    }

    #[test]
    fn test_verify() {
        let test = b"this is test text";
        let (private_key, public_key) = generate_keypair(2048);
        let signed = sign(private_key, test.to_vec());
        verify(public_key, test.to_vec(), signed);
    }
}
