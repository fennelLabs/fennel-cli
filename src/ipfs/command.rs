use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "fennel-ipfs")]
#[clap(about = "A Fennel tool for interacting with an IPFS node", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Add a given string to IPFS as a block
    #[clap()]
    AddString { file_content: String },

    /// Adds a file to IPFS as a block
    #[clap()]
    AddFile { filename: String },

    /// Retrieves a block from IPFS by CID
    #[clap()]
    GetFile { cid: String },

    /// Deletes a block from IPFS by CID
    #[clap()]
    DeleteFile { cid: String },
}
