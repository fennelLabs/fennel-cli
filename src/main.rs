#![feature(test)]

mod aes_tools;
mod fennel;
mod rsa_tools;

use aes_tools::*;
use clap::Parser;
use fennel::*;
use rsa_tools::*;

#[derive(Parser)]
struct Cli {
    recipient: String,
    #[clap(parse(from_os_str))]
    path: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();
}
