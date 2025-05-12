//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 12th, 2025
//! CS347 Advanced Software Design

use std::path::PathBuf;
use clap::{Parser, ArgGroup};
mod packet;
mod file_rw;
mod requester;
mod sender;
mod encryption;


#[derive(Parser)]
#[command(name = "p2p_client")]
#[command(about = "Send a file from one peer to another", long_about = None)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["send_file", "save_path"]),
))]
struct Cli {
    #[arg(short = 'f', long, group = "mode")]
    send_file: Option<PathBuf>,
    #[arg(short = 'p', long, group = "mode")]
    save_path: Option<PathBuf>,
    #[arg(required = true)]
    addr: String
}


/// Starts listening on `0.0.0.0:7878` for incoming connections and spawns a task to send to each `addr` in `send_addrs` on `[addr]:[port]`.
/// 
/// # Example
/// 
/// ```rust
/// let args: Vec<String> = args().collect();
/// run_client_server(&args[3..], args[2].clone(), args[1].clone());
/// ```
fn run_client_server(send_addr: String, send_file: Option<PathBuf>, save_path: Option<PathBuf>) {

 
    // if we passed a file we want to send, start the sending task
    if let Some(f) = send_file {
        println!("Starting sender task...");
        sender::start_listening(f);
        println!("Successfully started sender task");
    }

    // if we passed a save path for a downloaded file, start the requesting task
    if let Some(p) = save_path {
        requester::request_file(send_addr, "".to_string(), p);
    }
}

fn main() {
    let cli = Cli::parse();
    run_client_server(cli.addr, cli.send_file, cli.save_path);
}