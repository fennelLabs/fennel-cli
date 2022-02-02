extern crate test;

use crate::rsa_tools::*;
use test::Bencher;

#[bench]
fn bench_generate_2048(b: &mut Bencher) {
    b.iter(|| {
        generate_keypair(2048);
    });
}

#[bench]
fn bench_generate_4096(b: &mut Bencher) {
    b.iter(|| {
        generate_keypair(4096);
    });
}

#[bench]
fn bench_generate_8192(b: &mut Bencher) {
    b.iter(|| {
        generate_keypair(8192);
    });
}

#[bench]
fn bench_encrypt(b: &mut Bencher) {
    let test = b"this is test text";
    let (_, public_key) = generate_keypair(2048);
    b.iter(|| {
        encrypt(public_key.clone(), test.to_vec());
    });
}

#[bench]
fn bench_decrypt(b: &mut Bencher) {
    let test = b"this is test text";
    let (private_key, public_key) = generate_keypair(2048);
    let result = encrypt(public_key, test.to_vec());
    b.iter(|| {
        decrypt(private_key.clone(), result.clone());
    });
}

#[bench]
fn bench_sign(b: &mut Bencher) {
    let test = b"this is test text";
    let (private_key, _) = generate_keypair(2048);
    b.iter(|| {
        sign(private_key.clone(), test.to_vec().clone());
    });
}

#[bench]
fn bench_verify(b: &mut Bencher) {
    let test = b"this is test text";
    let (private_key, public_key) = generate_keypair(2048);
    let signed = sign(private_key, test.to_vec());
    b.iter(|| {
        verify(public_key.clone(), test.to_vec().clone(), signed.clone());
    });
}
