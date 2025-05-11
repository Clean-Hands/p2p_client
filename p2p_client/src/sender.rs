use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use std::path::PathBuf;
use tokio::runtime::Runtime;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use crate::encryption;
use crate::packet;
use crate::file_rw;



/// Writes the String `message` to all `TcpStream` objects in the Vec `streams`.
/// 
/// # Example
/// 
/// ```rust
/// let streams: Vec<TcpStream> = vec![stream1, stream2];
/// let message = String::from("Hello, world!");
/// send_to_all_connections(&streams, message);
/// ```
fn send_to_connection(stream: &mut TcpStream, nonce: &mut [u8; 12], cipher: &Aes256Gcm, message: [u8; packet::PACKET_SIZE]) {
    // encrypt message
    let enc_nonce = Nonce::from_slice(nonce);
    // this function call assumes that cipher is Some type, still need to check that cipher
    // is initialized correctly in start_sender_task
    let ciphertext = match encryption::encrypt_message(&enc_nonce, cipher, &message) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encryption failed: {e}");
            return; // don't think return is the correct action here. How do we want to handle an encryption fail?
        }
    };
    
    // increment nonce (in the struct itself)
    encryption::increment_nonce(nonce);

    if let Err(e) = stream.write_all(&ciphertext) {
        eprintln!("Failed to write to stream: {e}");
        return;
    }
}

/// Spawns a thread that handles sending messages to all IP addresses in `send_addrs`.
/// 
/// # Example
/// 
/// ```rust
/// let send_addrs: Vec<String> = vec![String::from("127.0.0.1"), String::from("127.0.0.2")];
/// let file_path = String::from("test.txt");
/// start_sender_task(send_addrs, file_path);
/// ```
pub async fn start_sender_task(mut stream: TcpStream, hash: String) {

    // carry out DH exchange
    let dh_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
    let dh_public_key = PublicKey::from(&dh_private_key);

    // send public key to listener
    if let Err(e) = stream.write_all(dh_public_key.as_bytes()) {
        eprintln!("Failed to send DH public key: {e}");
        return;
    }

    // wait for public key response from listener
    let mut public_key_bytes: [u8; 32] = [0; 32];
    stream.read_exact(&mut public_key_bytes).expect("Failed to read peer's public key");
    let peer_public_key = PublicKey::from(public_key_bytes);

    // compute and save shared secret
    let dh_shared_secret = dh_private_key.diffie_hellman(&peer_public_key);

    // generate and store AES cipher
    // TODO: handle the case where secret is not Some
    let key = Key::<Aes256Gcm>::from_slice(dh_shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let mut nonce = [0u8; 12];

    // TODO: this is hardcoded to be a test file. fix this later
    // TOTO: use hash to figuere out whiat fiile 
    let file_path = PathBuf::from("dracula.txt");

    // send filename
    if let Some(file_name) = file_path.file_name() {
        let file_name_packet = packet::encode_packet(file_name.to_string_lossy().into_owned().as_bytes().to_vec());
        send_to_connection(&mut stream, &mut nonce, &cipher, file_name_packet);
    }

    // send file hash
    let hash_bytes = match file_rw::read_file_bytes(&file_path) {
        Ok(hb) => hb,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    let file_hash_data = packet::compute_sha256_hash(&hash_bytes);
    let file_hash_packet = packet::encode_packet(file_hash_data);
    send_to_connection(&mut stream, &mut nonce, &cipher, file_hash_packet);

    // read file
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
                    send_to_connection(&mut stream, &mut nonce, &cipher, message);
                    return;
                }
            }
        }
        // encode the data and send the packet
        let message = packet::encode_packet(write_bytes);
        send_to_connection(&mut stream, &mut nonce, &cipher, message);
    }
}



pub fn start_listening(path: PathBuf) {

    // Create and enter a new async runtime
    let runtime = Runtime::new().expect("Failed to create a runtime");
    let _ = runtime.enter();
    
    println!("Starting listener...");
    let listen_addr = String::from("0.0.0.0:7878");
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
        runtime.spawn(start_sender_task(stream, "".to_string()));
    }
}