#![allow(deprecated)]

mod command;
use clap::Parser;
use command::{Cli, Commands};

use fennel_lib::{get_file, add_file, del_file};

pub fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::AddFile { filename } => {
            let result = add_file(filename);
            println!("{}", result);
        },
        Commands::GetFile { cid } => {
            let result = get_file(cid);
            println!("{}", result)
        },
        Commands::DeleteFile { cid } => {
            if del_file(cid) {
                println!("File deleted successfully");
            } else {
                println!("File failed to delete");
            }
        }
    }

}