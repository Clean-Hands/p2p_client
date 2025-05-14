//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 13th, 2025
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
    RequestCatalog { peer_address: String },
    Ping { peer_address: String },
    AddFile { file_path: String },
    RemoveFile { hash: String },
    ViewCatalog {},
    AddIP {}
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
        Mode::RequestCatalog { peer_address } => {}
        Mode::ViewCatalog {  } => {}
        // add-file command must be run from within p2p_client directory or the relative paths break
        Mode::AddFile { file_path } => {
            if let Err(e) = sender::add_file_to_catalog(&file_path) {
                eprintln!("Error adding file to catalog: {}", e);
                return;
            }
        }
        Mode::RemoveFile { hash } => {}
        Mode::Ping { peer_address } => {
            match requester::ping_addr(&peer_address) {
                Ok(result) => {
                    println!("{result}")
                },
                Err(e) =>  {
                    println!("{e}")
                }
            };
        }
        Mode::AddIP {  } => {}
    }
}