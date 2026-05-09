mod commands;
mod output;

use clap::Parser;
use commands::Cli;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    commands::run(cli)
}
