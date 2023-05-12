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
    /// Encode a Whiteflag JSON message to hex.
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Encode { json: String },

    /// Decode hex to a Whiteflag JSON message.
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Decode { hex: String },

    /// Begin or end a new Whiteflag session and print the message to submit to the network.
    #[clap()]
    Auth { logout: bool },

    /// Generate a message with the given code.
    #[clap()]
    Message { code: String },

    /// Generate a message with the given code and reference indicator. Used to update/discontinue messages.
    #[clap()]
    MessageWithReferenceIndicator {
        code: String,
        reference_indicator: String,
    },
}
