//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 12th, 2025
//! CS347 Advanced Software Design

use std::path::{Path, PathBuf};
use clap::{Parser, ArgGroup, Subcommand};
mod packet;
mod file_rw;
mod requester;
mod sender;
mod encryption;


#[derive(Parser)]
#[command(name = "p2p_client")]
#[command(about = "Send a file from one peer to another", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}


#[derive(Subcommand)]
enum Mode {
    Request { peer_address: String, file_hash: String, save_path: Option<PathBuf> },
    Send {},
    Catalog { peer_address: String },
    Ping { peer_address: String }
}


fn main() {

    let cli = Cli::parse();
    match cli.mode {
        Mode::Request { peer_address, file_hash, save_path } => {
            requester::request_file(peer_address, file_hash, save_path.unwrap_or(PathBuf::from(".")));
        }
        Mode::Send {} => {
            sender::start_listening();
        }
        Mode::Catalog { peer_address } => {}
        Mode::Ping { peer_address } => {}
    }
}