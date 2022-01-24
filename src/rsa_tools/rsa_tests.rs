#[cfg(test)]
mod rsa_tests {
    use super::super::rsa_tools::*;

    #[test]
    fn test_generate() {
        generate_keypair(2048);
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
}
