use criterion::{criterion_group, criterion_main, Criterion};
use fennel_lib::{generate_keypair, hash, FennelRSAPublicKey};

pub fn handle_generate_keypair(bits: usize) -> ([u8; 16], rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let (private_key, public_key): (rsa::RsaPrivateKey, rsa::RsaPublicKey) = generate_keypair(bits);

    let pub_key = FennelRSAPublicKey::new(public_key).unwrap();
    let fingerprint: [u8; 16] = hash(pub_key.as_u8())[0..16].try_into().unwrap();
    (fingerprint, private_key, pub_key.pk)
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("key generation", |b| {
        b.iter(|| handle_generate_keypair(4096))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
