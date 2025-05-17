//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 16th, 2025
//! CS347 Advanced Software Design

use clap::{Parser, Subcommand};
use std::path::PathBuf;
mod encryption;
mod file_rw;
mod listener;
mod packet;
mod requester;

#[derive(Parser)]
#[command(name = "p2p_client")]
#[command(about = "Send a file from one peer to another", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    #[command(about = "Subcommands related to requesting and downloading files")]
    Request {
        #[command(subcommand)]
        command: RequestCommand,
    },
    #[command(about = "Subcommands related to listening for requests and sending files")]
    Listen {
        #[command(subcommand)]
        command: ListenCommand,
    },
}

#[derive(Subcommand)]
enum RequestCommand {
    #[command(about = "Request a file from a peer")]
    File {
        peer_address: String,
        file_hash: String,
        save_path: Option<PathBuf>,
    },
    #[command(about = "Request the catalog of a specific peer")]
    Catalog { peer_address: String },
    #[command(about = "Check if a specific peer is available for requests")]
    Ping { peer_address: String },
    #[command(about = "Add an IP and an optional alias to your list of known peers")]
    AddIP {
        peer_address: String,
        alias: Option<String>,
    },
    #[command(about = "Remove an IP from your list of known peers")]
    RemoveIP { peer_address: String },
    #[command(about = "View your local list of known peers")]
    ViewIPS {},
}

#[derive(Subcommand)]
enum ListenCommand {
    #[command(about = "Start listening for incoming requests")]
    Start {},
    #[command(about = "Add a file to your local catalog")]
    AddFile { file_path: String },
    #[command(
        about = "Remove a file from your local catalog. Input \"DELETE-ALL\" in place of a hash to wipe the catalog clean"
    )]
    RemoveFile { hash: String },
    #[command(about = "View your local catalog")]
    ViewCatalog {},
}

fn main() {
    let cli = Cli::parse();
    match cli.mode {
        // parse the request subcommand
        Mode::Request { command } => match command {
            RequestCommand::File {
                peer_address,
                file_hash,
                save_path,
            } => {
                requester::request_file(
                    peer_address,
                    file_hash,
                    save_path.unwrap_or(PathBuf::from(".")),
                );
            }
            RequestCommand::Catalog { peer_address } => {
                if let Err(e) = requester::request_catalog(&peer_address) {
                    eprintln!("Error while requesting catalog: {e}")
                }
            }
            RequestCommand::Ping { peer_address } => {
                match requester::ping_addr(&peer_address) {
                    Ok(result) => {
                        println!("{result}")
                    }
                    Err(e) => {
                        println!("{e}")
                    }
                };
            }
            RequestCommand::AddIP {
                peer_address,
                alias,
            } => {
                // if no alias is specified, use the peer address
                let alias = alias.unwrap_or(peer_address.clone());
                if let Err(e) = requester::add_ip_to_peers(&peer_address, &alias) {
                    eprintln!("Error adding IP to list of peers: {e}");
                    return;
                }
            }
            RequestCommand::RemoveIP { peer_address } => {
                if let Err(e) = requester::remove_ip_from_peer_list(&peer_address) {
                    eprintln!("Error removing IP from list of peers: {e}");
                    return;
                }
            }
            RequestCommand::ViewIPS {} => {
                if let Err(e) = requester::view_peer_list() {
                    eprintln!("Unable to view peer_list: {}", e);
                    return;
                }
            }
        },

        // parse the listen subcommand
        Mode::Listen { command } => match command {
            ListenCommand::Start {} => {
                listener::start_listening();
            }
            ListenCommand::ViewCatalog {} => {
                if let Err(e) = listener::view_catalog() {
                    eprintln!("Unable to view catalog: {}", e);
                    return;
                }
            }
            ListenCommand::AddFile { file_path } => {
                if let Err(e) = listener::add_file_to_catalog(&file_path) {
                    eprintln!("Error adding file to catalog: {e}");
                    return;
                }
            }
            ListenCommand::RemoveFile { hash } => {
                if let Err(e) = listener::remove_file_from_catalog(&hash) {
                    eprintln!("Error removing file from catalog: {e}");
                    return;
                }
            }
        },
    }
}