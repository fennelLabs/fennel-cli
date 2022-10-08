#![allow(deprecated)]

mod command;
use std::fs;

use clap::Parser;
use command::{Cli, Commands};

use fennel_lib::{
    add_content_by_local_path, add_content_by_string, delete_content_by_cid, get_content_by_cid,
};

pub fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::AddString { file_content } => {
            let result = add_content_by_string(file_content).unwrap();
            fs::remove_file("upload.txt").unwrap();
            println!("{}", result);
        }
        Commands::AddFile { filename } => {
            let result = add_content_by_local_path(filename).unwrap();
            println!("{}", result);
        }
        Commands::GetFile { cid } => {
            let result = get_content_by_cid(cid).unwrap();
            println!("{}", result);
        }
        Commands::DeleteFile { cid } => {
            if delete_content_by_cid(cid).unwrap() {
                println!("File deleted successfully");
            } else {
                println!("File failed to delete");
            }
        }
    }
}
