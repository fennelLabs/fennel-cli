/// Handles operations related to RSA keypairs.

#[cfg(test)]
mod rsa_tests;
#[cfg(test)]
mod rsa_bench;

mod rsa_tools {
    use rand::rngs::OsRng;
    use rsa::pkcs8::Error;
    use rsa::{
        pkcs8::FromPrivateKey, pkcs8::FromPublicKey, pkcs8::ToPrivateKey, pkcs8::ToPublicKey,
        PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
    };

    /// Generate a public/private keypair and return it as RSA structs.
    pub fn generate_keypair(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        (private_key, public_key)
    }

    /// Given plaintext, encrypt it with the provided public key.
    pub fn encrypt(public_key: RsaPublicKey, plaintext: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        public_key
            .encrypt(&mut rng, padding, &plaintext[..])
            .expect("failed to encrypt")
    }

    /// Given a private key, decrypt ciphertext produced with its related public key.
    pub fn decrypt(private_key: RsaPrivateKey, ciphertext: Vec<u8>) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        private_key
            .decrypt(padding, &ciphertext)
            .expect("failed to decrypt")
    }

    /// Read in a keypair from a file.
    pub fn import_keypair_from_file(
        private_keyfile_path: std::path::PathBuf,
        public_keyfile_path: std::path::PathBuf
    ) -> Result<(RsaPrivateKey, RsaPublicKey), Error> {
        let pri = RsaPrivateKey::read_pkcs8_pem_file(private_keyfile_path)?;
        let pbk = RsaPublicKey::read_public_key_pem_file(public_keyfile_path)?;
        Ok((pri, pbk))
    }

    /// Write an in-memory keypair out to a file.
    pub fn export_keypair_to_file<'a>(
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        private_keyfile_path: std::path::PathBuf,
        public_keyfile_path: std::path::PathBuf
    ) -> Result<(), Error> {
        RsaPrivateKey::write_pkcs8_pem_file(&private_key, private_keyfile_path)?;
        RsaPublicKey::write_public_key_pem_file(&public_key, public_keyfile_path)?;
        Ok(())
    }
}
