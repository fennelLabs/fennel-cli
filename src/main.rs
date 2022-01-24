#![feature(test)]

mod rsa_tools;
mod aes_tools;

use clap::Parser;
use rsa_tools::*;
use aes_tools::*;

#[derive(Parser)]
struct Cli {
    recipient: String,
    #[clap(parse(from_os_str))]
    path: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();
}
