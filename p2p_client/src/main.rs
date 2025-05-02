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
use std::path::Path;

use file_rw::rename_file;
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
/// let streams: Vec<TcpStream> = vec![stream1, stream2];
/// let message = String::from("Hello, world!");
/// send_to_all_connections(&streams, message);
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
/// let file_path = String::from("test.txt");
/// start_sender_thread(send_addrs, port, file_path);
/// ```
fn start_sender_thread(send_addrs: Vec<String>, port: String, file_path: String) {

    thread::spawn(move || {
        // start a sender stream for every IP the user wants to talk to
        let mut senders: Vec<TcpStream> = vec![];
        for addr in send_addrs {
            senders.push(connect_sender_stream(&addr, &port));
        }

        let mut file_bytes = match file_rw::open_iterable_file(&file_path) {
            Ok(b) => b,
            Err(e) => {
                eprint!("{e}");
                return;
            }
        };

        // send only the file name + extension, w/o full path
        let filename = Path::new(&file_path).file_name().expect("Missing filename").to_str().expect("Unable to convert OsStr to str");

        // write packets until EOF 
        loop {
            let mut write_bytes: Vec<u8> = vec![];
            // just grab 400 bytes for now
            for _ in 0..400 {
                match file_bytes.next() {
                    Some(Ok(b)) => write_bytes.push(b),
                    Some(Err(e)) => eprintln!("Unable to read next byte: {e}"),
                    None => {
                        // when trying to read the next byte, we read EOF so send the last packet and return
                        let message = packet::encode_packet(String::from(filename), write_bytes.clone(), packet::compute_sha256_hash(&write_bytes));
                        send_to_all_connections(&senders, message);
                        return
                    }
                }
            }
            // encode the data and send the packet
            let message = packet::encode_packet(file_path.clone(), write_bytes.clone(), packet::compute_sha256_hash(&write_bytes));
            send_to_all_connections(&senders, message);
        }
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
            let mut received_file_name = String::from("file.tmp");
            let mut file = match file_rw::open_writable_file(&received_file_name) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };

            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        // End connection
                        println!("Partner disconnected");
                        return;
                    }
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("Failed to read from stream: {e}");
                        break;
                    }
                };

                let received_packet = match packet::decode_packet(buffer) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Unable to decode packet: {e}");
                        break;
                    }
                };

                // If the file name has not been updated yet, update it
                if received_file_name == "file.tmp" {
                    received_file_name = received_packet.filename;
                }
                
                let data_bytes = received_packet.data.len();
                match file.write(&received_packet.data) {
                    Ok(n) => {
                        if n != data_bytes {
                            eprintln!("Read {data_bytes} file bytes from stream, was only able to write {n} bytes to file")
                        }
                    },
                    Err(e) => eprintln!("Failed to write byte to file: {e}")
                }
            }

            if let Err(e) = rename_file(&mut file, &received_file_name) {
                eprintln!("{e}")
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