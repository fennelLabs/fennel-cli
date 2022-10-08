use clap::{AppSettings, Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "fennel-wf")]
#[clap(about = "A tool for managing Whiteflag messages", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Encode { json: String },

    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Decode { hex: String },

    #[clap()]
    Auth { logout: bool },

    #[clap()]
    Message { code: String },
}
