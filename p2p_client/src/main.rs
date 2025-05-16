//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 16th, 2025
//! CS347 Advanced Software Design

use std::path::PathBuf;
use clap::{Parser, Subcommand};
mod packet;
mod file_rw;
mod requester;
mod listener;
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
    #[command(about = "Request a file from a peer")]
    Request { peer_address: String, file_hash: String, save_path: Option<PathBuf> },
    #[command(about = "Start listening for incoming requests")]
    Listen {},
    #[command(about = "Request the catalog of a specific peer")]
    RequestCatalog { peer_address: String },
    #[command(about = "Check if a specific peer is available for requests")]
    Ping { peer_address: String },
    #[command(about = "Add a file to your local catalog")]
    AddFile { file_path: String },
    #[command(about = "Remove a file from your local catalog. Input 'DELETE-ALL' in place of a hash to wipe the catalog clean")]
    RemoveFile { hash: String },
    #[command(about = "View your local catalog")]
    ViewCatalog {},
    #[command(about = "Add an IP to your list of available peers. Optionally specify a human-readable alias")]
    AddIP { peer_address: String, alias: Option<String> },
    #[command(about = "Remove an IP from your list of available peers")]
    RemoveIP {  peer_address: String },
    #[command(about = "View your local list of IPs/peers")]
    ViewIPS {}
}


fn main() {

    let cli = Cli::parse();
    match cli.mode {
        Mode::Request { peer_address, file_hash, save_path } => {
            requester::request_file(peer_address, file_hash, save_path.unwrap_or(PathBuf::from(".")));
        }
        Mode::Listen {} => {
            listener::start_listening();
        }
        Mode::RequestCatalog { peer_address } => {
            if let Err(e) = requester::request_catalog(&peer_address) {
                eprintln!("Error while requesting catalog: {e}")
            }
        }
        Mode::ViewCatalog {} => {
            if let Err(e) = listener::view_catalog() {
                eprintln!("Unable to view catalog: {}", e);
                return;
            }
        }
        Mode::AddFile { file_path } => {
            if let Err(e) = listener::add_file_to_catalog(&file_path) {
                eprintln!("Error adding file to catalog: {e}");
                return;
            }
        }
        Mode::RemoveFile { hash } => {
            if let Err(e) = listener::remove_file_from_catalog(&hash) {
                eprintln!("Error removing file from catalog: {e}");
                return;
            }
        }
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
        Mode::AddIP { peer_address, alias } => {
            // if no alias is specified, use the peer address
            let alias = alias.unwrap_or_else(|| peer_address.clone());
            if let Err(e) = requester::add_ip_to_peers(&peer_address, &alias) {
                eprintln!("Error adding IP to list of peers: {e}");
                return;
            }
        }
        Mode::RemoveIP { peer_address } => {
            if let Err(e) = requester::remove_ip_from_peer_list(&peer_address) {
                eprintln!("Error removing IP from list of peers: {e}");
                return;
            }
        }
        Mode::ViewIPS {  } => {
            if let Err(e) = requester::view_peer_list() {
                eprintln!("Unable to view peer_list: {}", e);
                return;
            }            
        }
    }
}