//! main.rs
//! by Ruben Boero, Lazuli Kleinhans
//! April 29th, 2025
//! CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use std::thread::{self, sleep};
use std::time::Duration;
use std::env::args;
use std::process;
mod packet;
mod file_rw;


/// Connects a `TcpStream` object to the address `[send_ip]:[port]` and returns said object.
/// 
/// # Example
/// 
/// ```rust
/// let addr = String::from("127.0.0.1");
/// let port = String::from("7878");
/// let stream: TcpStream = connect_sender_stream(&addr, &port);
/// stream.write_all("Hello, world!".as_bytes());
/// ```
fn connect_sender_stream(send_ip: &String, port: &String) -> TcpStream {

    let send_addr: String = send_ip.to_owned() + ":" + port;
    // loop until connection is successful
    loop {
        println!("Attempting to connect to {send_addr}...");
        match TcpStream::connect(&send_addr) {
            Ok(s) => {
                println!("Connected to {send_addr}");
                return s;
            },
            Err(e) => {
                eprintln!("Failed to connect to {send_addr}: {e}");
                sleep(Duration::from_secs(1));
            }
        };
    }
}


/// Writes the String `message` to all `TcpStream` objects in the Vec `streams`.
/// 
/// # Example
/// 
/// ```rust
/// let senders: Vec<TcpStream> = vec![stream1, stream2];
/// let message = String::from("Hello, world!");
/// let stream: TcpStream = send_to_all_connections(&senders, message);
/// ```
fn send_to_all_connections(streams: &Vec<TcpStream>, message: [u8; 512]) {

    for mut stream in streams {
        if let Err(e) = stream.write_all(&message) {
            eprintln!("Failed to write to stream: {e}");
            return;
        }
    }
}


/// Spawns a thread that handles sending messages to all IP addresses in `send_addrs`.
/// 
/// # Example
/// 
/// ```rust
/// let send_addrs: Vec<String> = vec![String::from("127.0.0.1"), String::from("127.0.0.2")];
/// let port = String::from("7878");
/// let data = vec![104, 101, 108, 108, 111];
/// start_sender_thread(send_addrs, port, data);
/// ```
fn start_sender_thread(send_addrs: Vec<String>, port: String, file_path: String) {

    thread::spawn(move || {
        // start a sender stream for every IP the user wants to talk to
        let mut senders: Vec<TcpStream> = vec![];
        for addr in send_addrs {
            senders.push(connect_sender_stream(&addr, &port));
        }

        let file_bytes = match file_rw::read_file_bytes(&file_path) {
            Ok(b) => b,
            Err(e) => {
                eprint!("{e}");
                return;
            }
        };

        // send the packet
        let message = packet::encode_packet(file_path, file_bytes.clone(), packet::compute_sha256_hash(&file_bytes));
        send_to_all_connections(&senders, message);
    });
}


/// Starts listening on `0.0.0.0:[port]` for incoming connections and starts a thread to send to each `addr` in `send_addrs` on `[addr]:[port]`.
/// 
/// # Example
/// 
/// ```rust
/// let args: Vec<String> = args().collect();
/// run_client_server(&args[3..], args[2].clone(), args[1].clone());
/// ```
fn run_client_server(send_addrs: &[String], port: String, file_path: String) {
    
    println!("Starting listener...");
    let listen_addr = String::from("0.0.0.0:") + &port;
    let listener = match TcpListener::bind(&listen_addr) {
        Ok(l) => {
            println!("Client listening on {}", &listen_addr);
            l
        }
        Err(e) => {
            eprintln!("Failed to bind: {}", e);
            return;
        }
    };
    println!("Successfully started listener.");

    println!("Starting sender thread...");
    let mut send_addrs_clone: Vec<String> = vec![];
    for addr in send_addrs {
        send_addrs_clone.push(addr.clone());
    }

    start_sender_thread(send_addrs_clone, port, file_path);

    println!("Successfully started sender thread.");

    // start handling incoming data and printing it to the terminal
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };
    
        // create new thread for each incoming stream to handle more than one connection
        thread::spawn(move || {
            let mut buffer: [u8; 512] = [0; 512];
            loop {
                let num_bytes_read = match stream.read(&mut buffer) {
                    Ok(0) => {
                        println!("Partner disconnected");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from stream: {e}");
                        break;
                    }
                };

                let packet = match packet::decode_packet(buffer) {
                    Ok(p) => {
                        println!("Packet successfully decoded.");
                        p
                    },
                    Err(e) => {
                        eprintln!("Unable to decode packet: {e}");
                        return;
                    }
                };

                match file_rw::write_file_bytes(&String::from("received_file.txt"), &packet.data) {
                    Ok(_) => println!("Data successfully written to file."),
                    Err(e) => eprintln!("Unable to write bytes: {e}")
                }
            }
        });
    }
}


fn main() {

    // put all the command line arguments into a vector
    let args: Vec<String> = args().collect();
    if args.len() < 4 {
        eprintln!("Please specify a file path, port number, and any number of IP addresses to connect to.\nUsage: cargo run [file path] [port number] [IP address ...]");
        process::exit(1);  // exit with error code 1 (common failure)
    }

    run_client_server(&args[3..], args[2].clone(), args[1].clone());
}