use clap::Parser;
mod command;
use command::{Cli, Commands};

pub fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::Encode { json } => {
            println!("{}", wf_cli::WhiteflagCLICommands::encode(json).unwrap());
        }
        Commands::Decode { hex } => {
            println!("{}", wf_cli::WhiteflagCLICommands::decode(hex).unwrap());
        }
        Commands::Auth { logout } => {
            println!("{}", wf_cli::WhiteflagCLICommands::auth(*logout).unwrap());
        }
        Commands::Message { code } => {
            let message = wf_cli::WhiteflagCLICommands::message(code.to_owned()).unwrap();
            let hex = message.as_hex().unwrap();
            let cid = fennel_lib::add_content_by_string(&hex).unwrap();
            println!("hex: {}\ncid: {}", hex, cid);
        }
        Commands::MessageWithReferenceIndicator {
            code,
            reference_indicator,
        } => {
            let message = wf_cli::WhiteflagCLICommands::message_with_reference(
                code.to_string(),
                reference_indicator.to_string(),
            )
            .unwrap();
            let hex = message.as_hex().unwrap();
            let cid = fennel_lib::add_content_by_string(&hex).unwrap();
            println!("hex: {}\ncid: {}", hex, cid);
        }
    }
}
