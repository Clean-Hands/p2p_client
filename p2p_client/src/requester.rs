//! requester.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! May 19th, 2025
//! CS347 Advanced Software Design

use crate::encryption;
use crate::file_rw;
use crate::packet;
use aes_gcm::{
    Aes256Gcm, Key,
    aead::{KeyInit, OsRng},
};
use directories::ProjectDirs;
use hex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey};

type CatalogMap = HashMap<String, String>;
type PeerMap = HashMap<String, String>;



/// Gets the path to the list of peers. If catalog doesn't exist, a new one is created.
/// The list is stored in a static directory.
///
/// The location of static directory depends on the OS:
///
/// Linux: `/home/[user]/.local/share/p2p_client`
/// macOS: `/Users/[user]/Library/Application Support/com.LLR.p2p_client`
/// Windows: `C:\Users\[user]\AppData\Roaming\LLR\p2p_client\data`
fn get_peer_list_path() -> Result<PathBuf, String> {
    // find existing catalog or create a new one
    let mut peer_list_path = match ProjectDirs::from("com", "LLR", "p2p_client") {
        Some(d) => d.data_dir().to_owned().to_path_buf(),
        None => return Err(format!("No valid config directory could be located"))
    };

    if let Err(e) = fs::create_dir_all(&peer_list_path) {
        return Err(format!("Failed to create peers directory: {e}"));
    }

    peer_list_path.push("peers.json");

    Ok(peer_list_path)
}



/// Returns peer list as Hashmap given the absolute path to it
/// If there is no peers.json file, creates the file and returns an empty Hashmap
fn get_deserialized_peer_list(peer_list_path: &PathBuf) -> Result<CatalogMap, String> {
    let peer_list: PeerMap;

    if peer_list_path.exists() {
        let serialized = match fs::read_to_string(&peer_list_path) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string())
        };

        let deserialized = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(e) => return Err(e.to_string())
        };

        peer_list = deserialized;
    } else {
        // create the file if it doesn't exist
        let empty_list: PeerMap = HashMap::new();
        write_updated_peer_list(peer_list_path, &empty_list)?;
        peer_list = empty_list;
    }

    return Ok(peer_list);
}



/// Writes changes made to peer_list. If there is not file at the given path, will create a file an populate it with a bare json list: {}
fn write_updated_peer_list(peer_list_path: &PathBuf, peer_list: &PeerMap) -> Result<(), String> {
    // write updated peer list to peers.json
    let mut json_file = match File::create(peer_list_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open peer list file: {e}"))
    };

    let json = match serde_json::to_string_pretty(peer_list) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize peer list: {e}"))
    };

    let write_result = json_file.write_all(json.as_bytes());
    if let Err(e) = write_result {
        return Err(format!("Failed to write peer list file: {e}"));
    }

    Ok(())
}



/// Given an IP and alias for the IP as input, stores them in peers.json
/// found in a static directory. See get_peer_list_path() for peers.json locations
pub fn add_ip_to_peers(peer_addr: &String, alias: &String) -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive peer list path: {e}"))
    };

    let mut peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive peer list: {e}"))
    };

    // add/update entry in peer_list
    peer_list.insert(peer_addr.clone(), alias.clone());

    if let Err(e) = write_updated_peer_list(&peer_list_path, &peer_list) {
        return Err(format!("Error writing updated catalog: {}", e));
    }

    println!("Successfully added {alias} ({peer_addr}) to peer list");

    Ok(())
}



/// Given an IP as input, removes the associated entry from the peer list
///
/// If the input IP is `DELETE-ALL` then all entries in the catalog will be removed
pub fn remove_ip_from_peer_list(peer_addr: &String) -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive peer list path: {e}"))
    };

    let mut peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive peer list: {e}"))
    };

    if peer_addr == "DELETE-ALL" {
        peer_list.clear();
        println!("Successfully removed all entries from peer list");
    } else {
        match peer_list.remove(peer_addr) {
            None => println!("Entry \"{peer_addr}\" does not exist in catalog"),
            Some(f) => {
                let alias = String::from(f);
                println!("Successfully removed {alias} ({peer_addr}) from catalog")
            }
        };
    }

    // write updated catalog to catalog.json
    if let Err(e) = write_updated_peer_list(&peer_list_path, &peer_list) {
        return Err(format!("Error writing updated catalog: {}", e))
    }

    Ok(())
}



/// Displays the contents of the peer list
pub fn view_peer_list() -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retrieve peer list path: {e}"))
    };

    let peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retrieve peer list: {e}"))
    };

    if peer_list.is_empty() {
        println!("Peer list is empty.");
        return Ok(());
    }

    let max_ip_len = peer_list
        .keys()
        .map(|ip| ip.len())
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"IP Address".len())
        .max()
        .unwrap_or("IP Address".len());

    let max_alias_len = peer_list
        .values()
        .map(|alias| alias.len())
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"Alias".len())
        .max()
        .unwrap_or("Alias".len());

    // print table header
    println!(
        "| {:<max_ip_len$} | {:<width$}",
        "IP Address",
        "Alias",
        width = max_alias_len
    );

    // 2 gives space for the bar separating IP and alias
    println!(
        "|{}|{}",
        "=".repeat(2 + max_ip_len),
        "=".repeat(2 + max_alias_len)
    );

    // print each catalog entry
    for (hash, path) in peer_list.iter() {
        let file_name = Path::new(path)
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or("invalid UTF-8");

        println!(
            "| {:<max_ip_len$} | {:<width$}",
            hash,
            file_name,
            width = max_alias_len
        );
    }

    Ok(())
}



/// Ping an address to check that it is online. If TCP stream is established, stream is closed,
/// and Ok is returned. If TCP stream is not established, Err is returned.
pub fn ping_addr(addr: &String) -> Result<String, String> {
    let send_addr = format!("{addr}:7878");

    println!("Attempting to ping {send_addr}...");

    match TcpStream::connect(&send_addr) {
        Ok(_) => return Ok(format!("{addr} is online!")),
        Err(_) => return Err(format!("{addr} did not respond to ping"))
    }
}



/// Requests catalog from a given sender's IP address, then prints the contents of the catalog to stdout
pub fn request_catalog(addr: &String) -> Result<(), String> {
    let mut stream = connect_stream(&addr);

    let cipher = match perform_dh_handshake(&stream) {
        Ok(c) => c,
        Err(e) => return Err(format!("Diffie-Hellman handshake failed: {e}"))
    };
    
    // send mode packet
    let mut nonce: [u8; 12] = [0; 12];
    let req_catalog_packet = packet::encode_packet(String::from("request_catalog").into_bytes());
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, req_catalog_packet) {
        return Err(format!("Failed to send request for sender catalog {e}"));
    }

    // listen for response
    let mut buffer = [0u8; packet::PACKET_SIZE + 16];
    let mut catalog_bytes = Vec::new();
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let decrypted = match encryption::decrypt_message(&mut nonce, &cipher, &buffer) {
                    Ok(p) => p,
                    Err(e) => return Err(format!("Failed to decrypt packet: {e}"))
                };

                let packet = match packet::decode_packet(decrypted) {
                    Ok(p) => p,
                    Err(e) => return Err(format!("Failed to decode packet: {e}"))
                };

                catalog_bytes.extend_from_slice(&packet.data);
            },
            Err(e) => return Err(format!("Error reading from stream: {e}"))
        }
    }

    // print catalog
    let catalog_json = match String::from_utf8(catalog_bytes) {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to parse catalog as UTF-8: {e}"))
    };

    let catalog: CatalogMap = match serde_json::from_str(&catalog_json) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to deserialize catalog into hash map: {e}"))
    };

    if catalog.is_empty() {
        println!("Sender's catalog is empty.");
        return Ok(());
    }

    // dynamically determine max len name
    let max_name_len = catalog
        .values() // get iterator over the file paths stored in catalog
        // for each path, get the name of the file and its length
        .filter_map(|path| {
            let name = Path::new(path).file_name()?.to_str()?;
            Some(name.len())
        })
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"File Name".len())
        .max()
        .unwrap_or("File Name".len());

    let hash_len = 64;

    println!(
        "| {:<hash_len$} | {:<max_name_len$}",
        "SHA-256 Hash",
        "File Name"
    );

    // 2 gives space for the bar separating hash and path
    println!(
        "|{}|{}",
        "=".repeat(2 + hash_len),
        "=".repeat(2 + max_name_len)
    );

    for (hash, path) in catalog {
        let file_name = Path::new(&path)
            .file_name()
            .and_then(|os| os.to_str())
            .unwrap_or("invalid UTF-8");

        println!(
            "| {:<hash_len$} | {:<max_name_len$}",
            hash,
            file_name
        );
    }

    Ok(())
}



/// Receives file name and file hash from the sender
fn await_file_name_and_hash(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: &TcpStream,
) -> Result<(String, Vec<u8>), String> {
    // Aes256Gcm adds a 16 byte verification tag to the end of the ciphertext
    let mut buffer = [0u8; packet::PACKET_SIZE + 16];

    // listen for file name
    if let Err(e) = stream.read(&mut buffer) {
        return Err(format!("Failed to read from stream: {e}"));
    }
    let file_path = match encryption::decrypt_message(nonce, &cipher, &buffer) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}"))
    };
    let file_path_packet = match packet::decode_packet(file_path) {
        Ok(p) => p,
        Err(e) => return Err(format!("Unable to decode packet: {e}"))
    };
    let file_path = String::from_utf8_lossy(file_path_packet.data.as_slice());

    // listen for the filehash
    if let Err(e) = stream.read(&mut buffer) {
        return Err(format!("Failed to read from stream: {e}"));
    }
    let file_hash = match encryption::decrypt_message(nonce, &cipher, &buffer) {
        Ok(h) => h,
        Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}"))
    };
    let file_hash = packet::decode_packet(file_hash);
    let file_hash_packet = file_hash.unwrap();
    let file_hash = file_hash_packet.data.as_slice();

    Ok((String::from(file_path), file_hash.to_vec()))
}



/// Takes a stream opened by a TcpListener and handles incoming packets
fn save_incoming_file(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: TcpStream,
    mut save_path: PathBuf,
) -> Result<(), String> {
    // Aes256Gcm adds a 16 byte verification tag to the end of the ciphertext, so
    // buffer needs to be PACKET_SIZE + 16 bytes in size

    let file_name_and_hash = match await_file_name_and_hash(&cipher, nonce, &stream) {
        Ok(output) => output,
        Err(e) => return Err(e)
    };

    let file_name = file_name_and_hash.0;
    let file_hash = file_name_and_hash.1;
    println!("Downloading \"{file_name}\"...");

    save_path.push(&file_name);

    // read file
    let mut file = match file_rw::open_writable_file(&save_path) {
        Ok(f) => f,
        Err(e) => return Err(e)
    };

    // read bytes until peer disconnects
    loop {
        let mut buffer = [0u8; packet::PACKET_SIZE + 16];
        match stream.read(&mut buffer) {
            Ok(0) => {
                // End connection
                println!("Peer {} disconnected", stream.peer_addr().unwrap());

                // verify file hash is correct
                if let Err(e) = file.sync_all() {
                    return Err(format!("Failed to ensure all data written to file: {e}"));
                }

                let hash_bytes = match file_rw::read_file_bytes(&save_path) {
                    Ok(hb) => hb,
                    Err(e) => return Err(e),
                };
                let computed_file_hash = packet::compute_sha256_hash(&hash_bytes);

                if computed_file_hash != file_hash {
                    return Err(String::from("Failed to verify file hash. File not received correctly."))
                } else {
                    println!("Successfully downloaded \"{file_name}\"");
                }
                return Ok(());
            },
            Ok(n) if n != buffer.len() => {
                eprintln!("[WARNING] expected to read {} bytes from stream, only read {n}", buffer.len())
            },
            Ok(_) => (),
            Err(e) => return Err(format!("Failed to read from stream: {e}"))
        };

        // decrypt
        let plaintext = match encryption::decrypt_message(nonce, &cipher, &buffer) {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}"))
        };

        let received_packet = match packet::decode_packet(plaintext) {
            Ok(p) => p,
            Err(e) => return Err(format!("Unable to decode packet: {e}"))
        };

        let data_bytes = received_packet.data.len();
        match file.write(&received_packet.data) {
            Ok(n) => {
                if n != data_bytes {
                    return Err(format!("Read {data_bytes} file bytes from stream, was only able to write {n} bytes to file"))
                }
            },
            Err(e) => return Err(format!("Failed to write byte to file: {e}"))
        }
    }
}



/// Takes an opened TcpStream and performs the requester side of the Diffie-Hellman handshake
fn perform_dh_handshake(mut stream: &TcpStream) -> Result<Aes256Gcm, String> {
    // generate DH exchange info
    let local_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
    let local_public_key = PublicKey::from(&local_private_key);

    // read public key from peer
    let mut peer_public_key_bytes: [u8; 32] = [0; 32];
    stream.read_exact(&mut peer_public_key_bytes).expect("Failed to read peer's public key");
    let peer_public_key = PublicKey::from(peer_public_key_bytes);

    // send local public key to peer
    if let Err(e) = stream.write_all(local_public_key.as_bytes()) {
        return Err(format!("Failed to send local public key: {e}"));
    }

    // generate AES cipher to decrypt messages
    let shared_secret = local_private_key.diffie_hellman(&peer_public_key);
    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);
    return Ok(cipher);
}



/// Connects a `TcpStream` object to the address `[send_ip]:7878` and returns said object.
///
/// # Example
///
/// ```rust
/// let addr = String::from("127.0.0.1");
/// let stream: TcpStream = connect_stream(&addr);
/// stream.write_all("Hello, world!".as_bytes());
/// ```
fn connect_stream(addr: &String) -> TcpStream {
    let send_addr = format!("{addr}:7878");
    // loop until connection is successful
    loop {
        println!("Attempting to connect to {send_addr}...");
        match TcpStream::connect(&send_addr) {
            Ok(s) => {
                println!("Connected to {send_addr}");
                return s;
            }
            Err(e) => {
                eprintln!("Failed to connect to {send_addr}: {e}");
                sleep(Duration::from_secs(1));
            }
        };
    }
}



/// Send a request for a file by its `hash` to the IP `addr`, saving it in `file_path`
pub fn request_file(addr: String, hash: String, file_path: PathBuf) {
    let mut stream = connect_stream(&addr);

    let cipher = match perform_dh_handshake(&stream) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Diffie-Hellman handshake failed: {e}");
            return;
        }
    };
    let mut initial_nonce: [u8; 12] = [0; 12];

    // send mode packet
    let req_catalog_packet = packet::encode_packet(String::from("request_file").into_bytes());
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, req_catalog_packet) {
        eprintln!("Failed to send request for sender catalog {e}");
        return;
    }

    println!("Sending file request...");

    // send file hash
    let file_hash_packet = packet::encode_packet(hex::decode(&hash).expect("Unable to decode hexadecimal string"));
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, file_hash_packet) {
        // if receiving a file fails in any way, try again
        eprintln!("{e}");
        // TODO: find a better solution (request a packet again if it fails)
        //       this is just brute forcing the problem and terrible for huge files
        request_file(addr, hash, file_path);
        return;
    }

    // start receiving file packets, saving it in the directory file_path
    if let Err(e) = save_incoming_file(&cipher, &mut initial_nonce, stream, file_path.clone()) {
        // if receiving a file fails in any way, try again
        eprintln!("{e}");
        // TODO: find a better solution (request a packet again if it fails)
        //       this is just brute forcing the problem and terrible for huge files
        // request_file(addr, hash, file_path);
        return;
    }
}