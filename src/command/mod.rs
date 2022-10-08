use clap::{AppSettings, Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "fennel-cli")]
#[clap(about = "A tool for interacting with the Fennel Network", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// RSA encrypts a given string with a known public key for the given identity.
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Encrypt { plaintext: String, identity: u32 },

    /// RSA decrypts ciphertext encrypted for the current private key
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Decrypt { ciphertext: String },

    /// Begins a Diffie-Hellman handshake
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    GenerateEncryptionChannel {},

    /// Finishes a Diffie-Hellman handshake
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    AcceptEncryptionChannel {
        identity_id: u32,
        secret_key: String,
        public_key: String,
    },

    /// Encrypts a string with an AES secret
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    AESEncrypt {
        secret: String,
        public_key: String,
        plaintext: String,
    },

    /// Decrypts an AES-encrypted string
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    AESDecrypt {
        secret: String,
        public_key: String,
        ciphertext: String,
    },

    /// Print out the current session public key
    #[clap()]
    ShowPublicKey {},

    /// Verifies a message given a signature for an identity
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Verify {
        message: String,
        signature: String,
        public_key: String,
    },

    /// RSA signs the given message
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Sign { message: String },

    /// Runs a WebSocket RPC exposing crypto functions to parallel applications
    #[clap()]
    StartRPC {},
}
