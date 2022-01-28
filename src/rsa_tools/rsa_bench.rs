extern crate test;

#[cfg(test)]
mod rsa_bench {
    use super::super::rsa_tools::*;
    use super::test::Bencher;
    use std::path::PathBuf;

    #[bench]
    fn bench_generate(b: &mut Bencher) {
        b.iter(|| {
            let (private_key, public_key) = generate_keypair(2048);
            export_keypair_to_file(
                &private_key,
                &public_key,
                PathBuf::from("./PrivateBench.key"),
                PathBuf::from("./PublicBench.key"),
            )
            .expect("failed to export keys");
        });
    }

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let test = b"this is test text";
        let (_, public_key) = import_keypair_from_file(
            PathBuf::from("./PrivateBench.key"),
            PathBuf::from("./PublicBench.key"),
        )
        .expect("failed to import key");
        b.iter(|| {
            encrypt(public_key.clone(), test.to_vec());
        });
    }

    #[bench]
    fn bench_decrypt(b: &mut Bencher) {
        let test = b"this is test text";
        let (private_key, public_key) = import_keypair_from_file(
            PathBuf::from("./PrivateBench.key"),
            PathBuf::from("./PublicBench.key"),
        )
        .expect("failed to import key");
        let result = encrypt(public_key, test.to_vec());
        b.iter(|| {
            decrypt(private_key.clone(), result.clone());
        });
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let test = b"this is test text";
        let (private_key, _) = import_keypair_from_file(
            PathBuf::from("./PrivateBench.key"),
            PathBuf::from("./PublicBench.key"),
        )
        .expect("failed to import key");
        b.iter(|| {
            sign(private_key.clone(), test.to_vec().clone());
        });
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let test = b"this is test text";
        let (private_key, public_key) = import_keypair_from_file(
            PathBuf::from("./PrivateBench.key"),
            PathBuf::from("./PublicBench.key"),
        )
        .expect("failed to import key");
        let signed = sign(private_key, test.to_vec());
        b.iter(|| {
            verify(public_key.clone(), test.to_vec().clone(), signed.clone());
        });
    }
}
