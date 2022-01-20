use clap::Parser;

#[derive(Parser)]
struct Cli {
    recipient: String,
    #[clap(parse(from_os_str))]
    path: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();
}
