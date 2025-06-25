//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! June 6th, 2025
//! CS347 Advanced Software Design

use clap::{Parser, Subcommand};
use eframe::{self, egui::ViewportBuilder};
use tokio::runtime::Runtime;
use std::path::PathBuf;
mod encryption;
mod file_rw;
mod gui;
mod listener;
mod packet;
mod requester;

#[derive(Parser)]
#[command(name = "p2p_client")]
#[command(about = "Send a file from one peer to another", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Option<Mode>,
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
    #[command(about = "Request a file from a peer. Peer can be an alias added using 'add-ip' or an IP address")]
    File {
        peer: String,
        file_hash: String,
        save_path: Option<PathBuf>,
    },
    #[command(about = "Request the catalog of a specific peer. Peer can be an alias added using 'add-ip' or an IP address")]
    Catalog { peer: String },
    #[command(about = "Check if a specific peer is available for requests. Peer can be an alias added using 'add-ip' or an IP address")]
    Ping { peer: String },
    #[command(about = "Add an alias and an associated IP to your list of known peers")]
    AddIP { alias: String, peer_address: String },
    #[command(about = "Remove an IP from your list of known peers")]
    RemoveIP { peer: String },
    #[command(about = "View your local list of known peers")]
    ViewIPS {},
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
    ViewCatalog {},
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.mode {
        // parse the request subcommand
        Some(Mode::Request { command }) => match command {
            RequestCommand::File {
                peer,
                file_hash,
                save_path,
            } => {
                requester::request_file(peer, file_hash, save_path.unwrap_or(PathBuf::from("."))).await;
            }
            RequestCommand::Catalog { peer } => match requester::request_catalog(&peer) {
                Ok(result) => {
                    println!("{result}")
                }
                Err(e) => {
                    eprintln!("Error while requesting catalog: {e}")
                }
            },
            RequestCommand::Ping { peer } => match requester::ping_peer(&peer) {
                Ok(result) => {
                    println!("{result}")
                }
                Err(e) => {
                    println!("{e}")
                }
            },
            // TODO: do we want to change the name of the below command since we're using the alias
            // as the key rather than the IP, or do we still want to emphasize that the IP is what
            // is important?
            RequestCommand::AddIP {
                alias,
                peer_address,
            } => {
                if let Err(e) = requester::add_peer(&alias, &peer_address) {
                    eprintln!("Failed to add {alias} ({peer_address}) to list of peers: {e}");
                    return;
                }
            }
            RequestCommand::RemoveIP { peer } => {
                if let Err(e) = requester::remove_from_peer_list(&peer) {
                    eprintln!("Failed to remove {peer} from list of peers: {e}");
                    return;
                }
            }
            RequestCommand::ViewIPS {} => {
                if let Err(e) = requester::print_peer_list() {
                    eprintln!("Failed to print peer list: {e}");
                    return;
                }
            }
        },

        // parse the listen subcommand
        Some(Mode::Listen { command }) => match command {
            ListenCommand::Start {} => {
                listener::start_listening().await;
            }
            ListenCommand::ViewCatalog {} => {
                if let Err(e) = listener::print_catalog() {
                    eprintln!("Failed to print catalog: {e}");
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

        None => {
            // User didn't pass a CLI option, therefore open the GUI

            // start listening as soon as gui is started
            let runtime = Runtime::new().expect("Failed to create a runtime");
            let _ = runtime.enter();
            // TODO: gracefully exit this runtime when the GUI closes so we don't have the "Failed to accept connection:" error
            // Probably send some signal to tell it to wrap up listening before killing the runtime
            runtime.spawn(listener::start_listening());
            
            eframe::run_native(
                "P2P Client GUI",
                eframe::NativeOptions {
                    viewport: ViewportBuilder::default()
                        .with_inner_size([400.0, 300.0]) // Set window size
                        .with_resizable(false)
                        .with_maximize_button(false), 
                    ..Default::default() // Set all options other than `viewport` to their defaults
                },
                Box::new(|cc| Ok(Box::new(gui::P2PGui::new(cc)))),
            ).unwrap();

            // Kill the async listening task
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{listener, packet::compute_sha256_hash, requester};
    use serial_test::serial;
    use std::{
        fs,
        io::{BufWriter, Write},
        net::TcpListener,
        path::PathBuf,
    };
    use tempfile::NamedTempFile;
    use tokio::runtime::Runtime;

    /// create a temp file for testing
    fn create_large_file(size_in_mb: usize) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        {
            let mut writer = BufWriter::new(&file);
            let buffer = vec![b'x'; 1024]; // 1 KB

            for _ in 0..(size_in_mb * 1024) {
                writer.write_all(&buffer).unwrap();
            }
            writer.flush().unwrap();
        }
        file
    }

    async fn listen_for_one_connection() {
        println!("Starting listener...");
        let listen_addr = String::from("0.0.0.0:7878");
        let listener = match TcpListener::bind(&listen_addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind: {}", e);
                return;
            }
        };

        // start handling incoming connections
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        listener::start_sender_task(stream).await;
    }

    #[test]
    #[serial]
    /// send a file between two peers and verify its integrity
    fn test_send_file() {
        // initialize file
        let dummy_file = create_large_file(10);
        let bytes = fs::read(dummy_file.path()).unwrap();
        let file_hash = compute_sha256_hash(&bytes);

        if let Err(e) = listener::add_file_to_catalog(&dummy_file.path().display().to_string()) {
            panic!("Error adding file to catalog: {e}");
        }

        // start listener
        let runtime = Runtime::new().expect("Failed to create a runtime");
        let _ = runtime.enter();
        runtime.spawn(listen_for_one_connection());

        // request file
        let address = "127.0.0.1".to_string();
        let rq_file_hash = hex::encode(&file_hash);
        let runtime = Runtime::new().expect("Failed to create a runtime");
        let _ = runtime.enter();
        runtime.block_on(requester::request_file(address, rq_file_hash.clone(), PathBuf::from(".")));

        // validate the received file
        let file_name = dummy_file
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let file_path = PathBuf::from(".").join(&file_name);
        let data = fs::read(&file_path).expect("Failed to read file");
        let computed_hash = compute_sha256_hash(&data);

        assert_eq!(computed_hash, file_hash);

        // Cleanup
        if let Err(e) = listener::remove_file_from_catalog(&rq_file_hash) {
            eprintln!("Error removing file from catalog: {e}");
        }
        let _ = fs::remove_file(&file_path);
    }
}