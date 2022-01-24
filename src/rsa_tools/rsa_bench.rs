extern crate test;

#[cfg(test)]
mod rsa_bench {
    use super::super::rsa_tools::*;
    use super::test::Bencher;

    #[bench]
    fn test_generate(b: &mut Bencher) {
        b.iter(|| {
            generate_keypair(2048);
        });
    }

    #[bench]
    fn test_encrypt(b: &mut Bencher) {
        b.iter(|| {
            let test = b"this is test text";
            let (_, public_key) = generate_keypair(2048);
            encrypt(public_key, test.to_vec());
        });
    }

    #[bench]
    fn test_decrypt(b: &mut Bencher) {
        b.iter(|| {
            let test = b"this is test text";
            let (private_key, public_key) = generate_keypair(2048);
            let result = encrypt(public_key, test.to_vec());
            decrypt(private_key, result);
        });
    }
}
