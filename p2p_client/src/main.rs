//! main.rs
//! by Ruben Boero, Lazuli Kleinhans, Liam Keane
//! April 22nd, 2025
//! CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{self, Write, Read};
use std::thread::{self, sleep};
use std::time::Duration;
use std::env::args;
use std::process;
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
mod packet;
mod file_rw;

// Oliver advice:
// 1. potential async use case instead of threads?
// 2. use clap for creating CLI
// 3. consider using enum for private key and shared secret (nothing stored/Secret stored)

 struct ConnectionInfo {
    sender_stream: TcpStream,
    dh_public_key: PublicKey,
    dh_private_key: Option<EphemeralSecret>,
    dh_shared_secret: Option<SharedSecret>,
    cipher: Option<Aes256Gcm>,
    nonce: [u8; 12]
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
/// let senders: Vec<TcpStream> = vec![stream1, stream2];
/// let message = String::from("Hello, world!");
/// let stream: TcpStream = send_to_all_connections(&senders, message);
/// ```
fn send_to_all_connections(streams: &mut Vec<ConnectionInfo>, message: String) {

    for stream in streams {

        // encrypt message
        let nonce = Nonce::from_slice(&stream.nonce);
        let ciphertext = match stream.cipher.as_ref() {
            Some(cipher) => match cipher.encrypt(&nonce, message.as_ref()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Encryption failed: {}", e);
                    continue; // or `return` if you want to exit entirely
                }
            },
            None => {
                eprintln!("Failed to initialize cipher");
                continue; // or `return`
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
/// let username = String::from("Alice");
/// start_sender_thread(send_addrs, port, username);
/// ```
fn start_sender_thread(send_addrs: Vec<String>, port: String, username: String) {

    thread::spawn(move || {
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
            
            // debug
            println!("SENDER PUBLIC KEY {:?}:", public_key_bytes);
            if let Some(secret) = &connection.dh_shared_secret {
                println!("SENDER SHARED SECRET: {:02x?}", secret.as_bytes());
            }

            // generate and store AES cipher
            // TODO: handle the case where secret is not Some
            if let Some(secret) = connection.dh_shared_secret.take() {
                let key = Key::<Aes256Gcm>::from_slice(secret.as_bytes());
                connection.cipher = Some(Aes256Gcm::new(key));
            }
            
        }

        // commence encrypted messaging
        loop {
            let mut message = String::new();
            // if let tries to match the output of read_line to Err, if it does match, it prints error message,
            // but if there is no error (Ok returned from read_line), then nothing happens
            if let Err(e) = io::stdin().read_line(&mut message) {
                eprintln!("Failed to read line: {e}");
                return;
            }

            if message.trim() == String::from("/exit"){
                println!("Goodbye!");
                // tell other users you disconnected
                send_to_all_connections(&mut senders, format!("[{username} disconnected]"));
                process::exit(0);
            }

            // send your message along with your username so others know who sent it
            message = format!("[{username}] {message}");
            send_to_all_connections(&mut senders, message);
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
fn run_client_server(send_addrs: &[String], port: String, username: String) {
    
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
    start_sender_thread(send_addrs_clone, port, username);
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
            // generate DH exchange info
            let my_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
            let my_public_key = PublicKey::from(&my_private_key);

            // read public key from sender
            let mut public_key_bytes = [0u8; 32];
            stream.read_exact(&mut public_key_bytes).expect("Failed to read peer's public key");
            let peer_public_key = PublicKey::from(public_key_bytes);

            // send our public key to sender
            if let Err(e) = stream.write_all(my_public_key.as_bytes()) {
                eprintln!("Failed to send my public key: {e}");
                return;
            }

            // generate shared secret
            let shared_secret = my_private_key.diffie_hellman(&peer_public_key);

            //debug
            println!("RECEIVER PUBLIC KEY {:?}:", public_key_bytes);
            println!("RECEIVER SHARED SECRET {:02x?}:", shared_secret.as_bytes());

            // generate AES cipher to decrypt messages
            let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
            let cipher = Aes256Gcm::new(key);
            let mut initial_nonce: [u8; 12] = [0; 12];       
            
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

                // decrypt
                let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&initial_nonce);

                increment_nonce(&mut initial_nonce);

                match cipher.decrypt(&nonce, &buffer[..num_bytes_read]) {
                    Ok(plaintext) => {
                        let received = String::from_utf8_lossy(&plaintext);
                        println!("{}", received.trim());
                    }
                    Err(e) => {
                        eprintln!("Failed to decrypt message: {e}");
                    }
                }
            }
        });
    }
}


fn main() {

    // put all the command line arguments into a vector
    let args: Vec<String> = args().collect();
    if args.len() < 4 {
        eprintln!("Please specify a username, port number, and any number of IP addresses to connect to.\nUsage: cargo run [username] [port number] [IP address ...]");
        process::exit(1);  // exit with error code 1 (common failure)
    }

    run_client_server(&args[3..], args[2].clone(), args[1].clone());
}