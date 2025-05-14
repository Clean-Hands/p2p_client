//! sender.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! May 12th, 2025
//! CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use std::path::{PathBuf, Path};
use std::fs::{File, copy, create_dir_all, read_to_string};
use std::collections::HashMap;
use tokio::runtime::Runtime;
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use x25519_dalek::{EphemeralSecret, PublicKey};
use aes_gcm::{
    aead::{KeyInit, OsRng},
    Aes256Gcm, Key
};
use crate::encryption;
use crate::packet;
use crate::file_rw;

type CatalogMap = HashMap<String, String>; // hash is key, filename is value

/// Copies file from given location into the sender files directory. 
/// The code must be run from the p2p_client directory or the paths to the sender files directory break
pub fn add_file_to_catalog(file_path: &String) -> Result<(), String> {
    let file_path_buf = PathBuf::from(file_path);
    
    // get hash of file
    let file_bytes = match file_rw::read_file_bytes(&file_path_buf) {
        Ok(b) => b,
        Err(e) => return Err(e)
    };

    let file_hash = packet::compute_sha256_hash(&file_bytes);
    // TODO, change the hash to a represenatation easier to deal with than base 10
    // https://users.rust-lang.org/t/how-do-i-convert-vec-of-i32-to-string/18669/5
    let file_hash_str: String = file_hash.into_iter().map(|i| i.to_string()).collect::<String>();

    // if sender-catalog/sender-files doesn't exist, create it
    let destination_dir = Path::new("sender_catalog/sender_files");
    if let Err(e) = create_dir_all(&destination_dir) {
        return Err(format!("Failed to create sender files directory: {e}"));
    }

    // copy file into sender-files using its hash as filename
    let destination_path = destination_dir.join(&file_hash_str);
    if let Err(e) = copy(&file_path_buf, &destination_path) {
        return Err(format!("Failed to copy file: {e}"));
    }
    println!("Successfully copied '{file_path}' into sender_files");

    // load existing catalog or create a new one
    let catalog_path = Path::new("sender_catalog/sender_catalog.json");
    let mut catalog: CatalogMap;

    if catalog_path.exists() {
        let serialized = match read_to_string(&catalog_path) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };

        let deserialized = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(e) => return Err(e.to_string()),
        };

        catalog = deserialized;
    } else {
        catalog = HashMap::new();
    }

    // add/update entry in catalog
    let filename = file_path_buf.file_name().ok_or("File path has no file name")?.to_string_lossy().into_owned();
    catalog.insert(file_hash_str, filename);

    // write updated catalog to sender-catalog.json
    let mut file = match File::create(&catalog_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open catalog file: {e}")),
    };

    let json = match serde_json::to_string_pretty(&catalog) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize catalog: {e}")),
    };

    let write_result = file.write_all(json.as_bytes());
    if let Err(e) = write_result {
        return Err(format!("Failed to write catalog file: {e}"));
    }
    
    return Ok(())
}


/// Send a file name and its hash to the requesting TcpStream
// should probably delete this since requester will alreaedy know the filename and hash
fn send_file_name_and_hash(file_path: &PathBuf, cipher: &Aes256Gcm, mut nonce: &mut [u8; 12], mut stream: &mut TcpStream) -> Result<(), String> {
    
    // send file name
    match file_path.file_name() {
        Some(f) => {
            let file_name_packet = packet::encode_packet(f.to_string_lossy().into_owned().as_bytes().to_vec());
            encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_name_packet);
        },
        None => return Err(format!("Unable to get file name from file path"))
    }

    // send file hash
    let hash_bytes = match file_rw::read_file_bytes(&file_path) {
        Ok(h) => h,
        Err(e) => return Err(e)
    };
    let file_hash_data = packet::compute_sha256_hash(&hash_bytes);
    let file_hash_packet = packet::encode_packet(file_hash_data);
    encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_hash_packet);
    return Ok(())
}


/// An asynchronous task that handles sending a file over `stream`
pub async fn start_sender_task(mut stream: TcpStream) {

    // println!("Connecting to {:?}...", stream.peer_addr().unwrap());

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
    match stream.read(&mut public_key_bytes) {
        Ok(n) if n == 0 => return, // 0  bytes read indicates ping was sent, so do not continue connection
        Ok(n) if n != public_key_bytes.len() => {
            eprintln!("Incorrect number of bytes received for peer's public key. Expected {} bytes but recieved {} bytes", public_key_bytes.len(), n);
            return;
        },
        Ok(_) => {},
        Err(e) => {
            eprintln!("Failed to read peer's public key: {e}");
            return;
        }
    };
    
    let peer_public_key = PublicKey::from(public_key_bytes);

    // compute and save shared secret
    let dh_shared_secret = dh_private_key.diffie_hellman(&peer_public_key);

    // generate and store AES cipher
    let key = Key::<Aes256Gcm>::from_slice(dh_shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let mut initial_nonce = [0u8; 12];

    println!("Successfully connected to {:?}", stream.peer_addr().unwrap());

    let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&initial_nonce);

    let mut buffer = [0u8; packet::PACKET_SIZE + 16];
    if let Err(e) = stream.read(&mut buffer) {
        eprintln!("Failed to read from stream: {e}");
        return;
    }

    let file_hash_packet = match encryption::decrypt_message(&nonce, &cipher, &buffer) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to decrypt ciphertext: {e}");
            return;
        }
    };

    let file_hash_packet = match packet::decode_packet(file_hash_packet) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Unable to decode packet: {e}");
            return;
        }
    };
    let file_hash = String::from_utf8(file_hash_packet.data).expect("Unable to decode file hash");

    encryption::increment_nonce(&mut initial_nonce);

    // TODO: actually figure out what file this hash refers to; right now we are just taking a file name in instead of the hash
    let file_path = PathBuf::from(&file_hash);

    if let Err(e) = send_file_name_and_hash(&file_path, &cipher, &mut initial_nonce, &mut stream) {
        eprintln!("Failed to send file name and hash to peer: {e}");
        return;
    }

    // read file
    let mut file_bytes = match file_rw::open_iterable_file(&file_path) {
        Ok(b) => b,
        Err(e) => {
            eprint!("{e}");
            return;
        }
    };

    println!("Beginning to send \"{file_hash}\" to {:?}...", stream.peer_addr().unwrap());

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
                    encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, message);
                    println!("File \"{file_hash}\" successfully sent to {:?}", stream.peer_addr().unwrap());
                    return;
                }
            }
        }
        // encode the data and send the packet
        let message = packet::encode_packet(write_bytes);
        encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, message);
    }
}



pub fn start_listening() {
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

        // println!("\nGot a request from {:?}", stream.peer_addr().unwrap());
    
        // spawn a new task for each incoming stream to handle more than one connection
        runtime.spawn(start_sender_task(stream));
    }
}