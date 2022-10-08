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
            println!(
                "{}",
                wf_cli::WhiteflagCLICommands::auth(logout.clone()).unwrap()
            );
        }
        Commands::Message { code } => {
            let message = wf_cli::WhiteflagCLICommands::message(code.to_owned()).unwrap();
            println!("{}", message);
        }
    }
}
