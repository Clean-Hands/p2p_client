//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! May 6th, 2025
//! CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use std::thread::sleep;
use std::time::Duration;
use std::env::args;
use std::process;
use tokio::runtime::Runtime;
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
mod packet;
mod file_rw;

// Oliver advice:
// 1. use clap for creating CLI
// 2. consider using enum for private key and shared secret (nothing stored/Secret stored)

 struct ConnectionInfo {
    sender_stream: TcpStream,
    dh_public_key: PublicKey,
    dh_private_key: Option<EphemeralSecret>,
    dh_shared_secret: Option<SharedSecret>,
    cipher: Option<Aes256Gcm>,
    nonce: [u8; 12]
}

/// encrypt message given nonce, cipher, and message
fn encrypt_message(nonce: &GenericArray<u8, U12>, cipher: &Aes256Gcm, message: &[u8; packet::PACKET_SIZE]) -> Result<Vec<u8>, String> {
    match cipher.encrypt(&nonce, message.as_ref()) {
        Ok(c) => {return Ok(c)}
        Err(e) => {
            return Err(format!("Encryption failed: {}", e));

        }
    }; 
}

// TODO, this seems janky and unintended within aes_gcm crate, look for better way to incr nonce
// should probably be incrementing a bit a time, not a byte
/// increment the nonce within the struct
fn increment_nonce(nonce: &mut [u8; 12]) {
    let mut carry = true;

    for byte in nonce.iter_mut().rev() {
        if carry {
            let (new_byte, overflow) = byte.overflowing_add(1);
            // dereference nonce's byte and update its actual value
            *byte = new_byte;
            carry = overflow;
        } else {
            break;
        }
    }
}


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
fn send_to_all_connections(streams: &mut Vec<ConnectionInfo>, message: [u8; packet::PACKET_SIZE]) {

    for stream in streams {

        // encrypt message
        let nonce = Nonce::from_slice(&stream.nonce);
        // this function call assumes that cipher is Some type, still need to check that cipher
        // is initialized correctly in start_sender_task
        let ciphertext = match encrypt_message(&nonce, stream.cipher.as_ref().unwrap(), &message) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Encryption failed: {e}");
                continue; // don't think continue is the correct action here. How do we want to handle 
                          // an encryption fail?
            }
        };
        
        // increment nonce (in the struct itself)
        increment_nonce(&mut stream.nonce);

        if let Err(e) = stream.sender_stream.write_all(&ciphertext) {
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
/// start_sender_task(send_addrs, port, file_path);
/// ```
async fn start_sender_task(send_addrs: Vec<String>, port: String, file_path: String) {
    // start a sender stream for every IP the user wants to talk to
    let mut senders: Vec<ConnectionInfo> = vec![];
    for addr in &send_addrs {
        let sender_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let stream = connect_sender_stream(addr, &port);
        let info = ConnectionInfo {
            sender_stream: stream,
            dh_public_key: PublicKey::from(&sender_secret),
            dh_private_key: Some(sender_secret),
            dh_shared_secret: None,
            cipher: None,
            nonce: [0u8; 12]
        };
        senders.push(info);
    }

    // carry out DH exchange
    for connection in &mut senders {
        // send public key to listener
        if let Err(e) = connection.sender_stream.write_all(connection.dh_public_key.as_bytes()) {
            eprintln!("Failed to send DH public key: {e}");
            return;
        }

        // wait for public key response from listener
        let mut public_key_bytes = [0u8; 32];
        connection.sender_stream.read_exact(&mut public_key_bytes).expect("Failed to read peer's public key");
        let peer_public_key = PublicKey::from(public_key_bytes);

        // compute and save shared secret in struct
        if let Some(secret) = connection.dh_private_key.take() {
            connection.dh_shared_secret = Some(secret.diffie_hellman(&peer_public_key));
        }

        // generate and store AES cipher
        // TODO: handle the case where secret is not Some
        if let Some(secret) = connection.dh_shared_secret.take() {
            let key = Key::<Aes256Gcm>::from_slice(secret.as_bytes());
            connection.cipher = Some(Aes256Gcm::new(key));
        }
    }

    let mut file_bytes = match file_rw::open_iterable_file(&file_path) {
        Ok(b) => b,
        Err(e) => {
            eprint!("{e}");
            return;
        }
    };

    // write packets until EOF 
    loop {
        let mut write_bytes: Vec<u8> = vec![];
        // subtract 2 for the data_length bytes
        let max_bytes = packet::PACKET_SIZE - 2;
        for _ in 0..max_bytes {
            match file_bytes.next() {
                Some(Ok(b)) => write_bytes.push(b),
                Some(Err(e)) => eprintln!("Unable to read next byte: {e}"),
                None => {
                    // when trying to read the next byte, we read EOF so send the last packet and return
                    let message = packet::encode_packet(write_bytes);
                    send_to_all_connections(&mut senders, message);
                    return
                }
            }
        }
        // encode the data and send the packet
        let message = packet::encode_packet(write_bytes);
        send_to_all_connections(&mut senders, message);
    }
}


async fn handle_incoming_connection(mut stream: TcpStream) {

    println!("Received incoming connection from {}", stream.peer_addr().unwrap());
    // generate DH exchange info
    let local_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
    let local_public_key = PublicKey::from(&local_private_key);

    // read public key from peer
    let mut peer_public_key_bytes: [u8; 32] = [0; 32];
    stream.read_exact(&mut peer_public_key_bytes).expect("Failed to read peer's public key");
    let peer_public_key = PublicKey::from(peer_public_key_bytes);

    // send our public key to peer
    if let Err(e) = stream.write_all(local_public_key.as_bytes()) {
        eprintln!("Failed to send local public key: {e}");
        return;
    }

    // generate AES cipher to decrypt messages
    let shared_secret = local_private_key.diffie_hellman(&peer_public_key);
    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let mut initial_nonce: [u8; 12] = [0; 12];       
    
    // Aes256Gcm adds a 16 byte verification tag to the end of the ciphertext, so 
    // buffer needs to be PACKET_SIZE + 16 bytes in size
    let mut buffer: [u8; 528] = [0; 528];
    let mut file = match file_rw::open_writable_file(&String::from("file.tmp")) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    loop {
        let num_bytes_read = match stream.read(&mut buffer) {
            Ok(0) => {
                // End connection
                println!("Peer {} disconnected", stream.peer_addr().unwrap());
                return;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("Failed to read from stream: {e}");
                return;
            }
        };

        // decrypt
        let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&initial_nonce);
        increment_nonce(&mut initial_nonce);
        let plaintext = match cipher.decrypt(&nonce, &buffer[..num_bytes_read]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to decrypt message: {e}");
                return;
            }
        };

        // convert the plaintext Vec into an array
        let mut packet_array: [u8; packet::PACKET_SIZE] = [0; packet::PACKET_SIZE];
        for i in 0..packet::PACKET_SIZE {
            packet_array[i] = plaintext[i];
        }

        let received_packet = match packet::decode_packet(packet_array) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Unable to decode packet: {e}");
                return;
            }
        };
        
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

    // Create and enter a new async runtime
    let rt = Runtime::new().expect("Failed to create a runtime");
    let _ = rt.enter();
    
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
    println!("Successfully started listener");

    println!("Starting sender task...");
    let mut send_addrs_clone: Vec<String> = vec![];
    for addr in send_addrs {
        send_addrs_clone.push(addr.clone());
    }

    rt.spawn(start_sender_task(send_addrs_clone, port, file_path));

    println!("Successfully started sender task");

    // start handling incoming connections
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };
    
        // spawn a new task for each incoming stream to handle more than one connection
        rt.spawn(handle_incoming_connection(stream));
    }
}


fn main() {

    // put all the command line arguments into a Vec
    let args: Vec<String> = args().collect();
    if args.len() < 4 {
        eprintln!("Please specify a file path, port number, and any number of IP addresses to connect to.\nUsage: cargo run [file path] [port number] [IP address ...]");
        process::exit(1);
    }

    run_client_server(&args[3..], args[2].clone(), args[1].clone());
}