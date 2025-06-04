//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! June 4th, 2025
//! CS347 Advanced Software Design

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use eframe::{self, egui};
mod encryption;
mod file_rw;
mod listener;
mod packet;
mod requester;
mod gui;

#[derive(Parser)]
#[command(name = "p2p_client")]
#[command(about = "Send a file from one peer to another", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Option<Mode>
}

#[derive(Subcommand)]
enum Mode {
    #[command(about = "Subcommands related to requesting and downloading files")]
    Request {
        #[command(subcommand)]
        command: RequestCommand
    },
    #[command(about = "Subcommands related to listening for requests and sending files")]
    Listen {
        #[command(subcommand)]
        command: ListenCommand
    }
}

#[derive(Subcommand)]
enum RequestCommand {
    #[command(about = "Request a file from a peer. Peer can be an alias added using 'add-ip' or an IP address")]
    File {
        peer: String,
        file_hash: String,
        save_path: Option<PathBuf>
    },
    #[command(about = "Request the catalog of a specific peer. Peer can be an alias added using 'add-ip' or an IP address")]
    Catalog { peer: String },
    #[command(about = "Check if a specific peer is available for requests. Peer can be an alias added using 'add-ip' or an IP address")]
    Ping { peer: String },
    #[command(about = "Add an alias and an associated IP to your list of known peers")]
    AddIP {
        alias: String,
        peer_address: String
    },
    #[command(about = "Remove an IP from your list of known peers")]
    RemoveIP { peer: String },
    #[command(about = "View your local list of known peers")]
    ViewIPS {}
}

#[derive(Subcommand)]
enum ListenCommand {
    #[command(about = "Start listening for incoming requests")]
    Start {},
    #[command(about = "Add a file to your local catalog")]
    AddFile { file_path: String },
    #[command(about = "Remove a file from your local catalog. Input \"DELETE-ALL\" in place of a hash to wipe the catalog clean")]
    RemoveFile { hash: String },
    #[command(about = "View your local catalog")]
    ViewCatalog {}
}

fn main() {
    let cli = Cli::parse();
    match cli.mode {
        // parse the request subcommand
        Some(Mode::Request { command }) => match command {
            RequestCommand::File {
                peer,
                file_hash,
                save_path
            } => {
                requester::request_file(
                    peer,
                    file_hash,
                    save_path.unwrap_or(PathBuf::from("."))
                );
            },
            RequestCommand::Catalog { peer } => {
                match requester::request_catalog(&peer) {
                    Ok(result) => {
                        println!("{result}")
                    },
                    Err(e) => {
                        eprintln!("Error while requesting catalog: {e}")
                    }
                }
            },
            RequestCommand::Ping { peer } => {
                match requester::ping_addr(&peer) {
                    Ok(result) => {
                        println!("{result}")
                    },
                    Err(e) => {
                        println!("{e}")
                    }
                }
            },
            // TODO: do we want to change the name of the below command since we're using the alias
            // as the key rather than the IP, or do we still want to emphasize that the IP is what
            // is important?
            RequestCommand::AddIP {
                alias,
                peer_address
            } => {
                if let Err(e) = requester::add_ip_to_peers(&alias, &peer_address) {
                    eprintln!("Failed to add {alias} ({peer_address}) to list of peers: {e}");
                    return;
                }
            },
            RequestCommand::RemoveIP { peer } => {
                if let Err(e) = requester::remove_ip_from_peer_list(&peer) {
                    eprintln!("Failed to remove {peer} from list of peers: {e}");
                    return;
                }
            },
            RequestCommand::ViewIPS {} => {
                if let Err(e) = requester::view_peer_list() {
                    eprintln!("Unable to view peer_list: {}", e);
                    return;
                }
            }
        },

        // parse the listen subcommand
        Some(Mode::Listen { command }) => match command {
            ListenCommand::Start {} => {
                listener::start_listening();
            },
            ListenCommand::ViewCatalog {} => {
                if let Err(e) = listener::view_catalog() {
                    eprintln!("Unable to view catalog: {}", e);
                    return;
                }
            },
            ListenCommand::AddFile { file_path } => {
                if let Err(e) = listener::add_file_to_catalog(&file_path) {
                    eprintln!("Error adding file to catalog: {e}");
                    return;
                }
            },
            ListenCommand::RemoveFile { hash } => {
                if let Err(e) = listener::remove_file_from_catalog(&hash) {
                    eprintln!("Error removing file from catalog: {e}");
                    return;
                }
            }
        },

        None => {
            // User didn't pass a CLI option, therefore open the GUI            
            eframe::run_native(
                "P2P Client GUI",
                eframe::NativeOptions { 
                    viewport: egui::ViewportBuilder::default().with_inner_size([400.0, 300.0]), // Set window size
                    ..Default::default() // Set all options other than `viewport` to their defaults
                },
                Box::new(|cc| Ok(Box::new(gui::P2PGui::new(cc))))
            ).unwrap();
        }
    }
}