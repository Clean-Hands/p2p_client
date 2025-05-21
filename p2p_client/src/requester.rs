//! requester.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! May 20th, 2025
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
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use x25519_dalek::{EphemeralSecret, PublicKey};
use std::time::{Instant, Duration};

type CatalogMap = HashMap<String, String>;
type PeerMap = HashMap<String, String>;

const SPINNER: &[char] = &['|', '/', '-', '\\'];
const BAR_WIDTH: usize = 30;



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



/// Connects a `TcpStream` object to the address `[addr]:7878` and returns said object.
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
    let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
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



/// Receives file name and its size from the sender
fn await_file_metadata(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: &TcpStream,
) -> Result<(String, f64), String> {
    // listen for file name
    let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
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

    // listen for the file size
    if let Err(e) = stream.read(&mut buffer) {
        return Err(format!("Failed to read from stream: {e}"));
    }
    let packet_bytes = match encryption::decrypt_message(nonce, &cipher, &buffer) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}"))
    };
    let file_size_packet = match packet::decode_packet(packet_bytes) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decode packet: {e}"))
    };
    let file_size_array: [u8; 8] = file_size_packet.data.try_into().expect("Vec must have exactly 8 elements");
    let file_size = u64::from_be_bytes(file_size_array);

    Ok((String::from(file_path), file_size as f64))
}



/// prints a download progress bar to stdout (every 100ms)
fn print_loading_bar(bytes_sent: f64, total_bytes: f64, tick: usize) {
    let percent = bytes_sent / total_bytes;
    let filled = (percent as f64 * BAR_WIDTH as f64).round() as usize;
    let empty = BAR_WIDTH - filled;
    let spinner = SPINNER[tick % SPINNER.len()];

    let progress_bar = format!(
        "[{}{}]",
        "=".repeat(filled),
        " ".repeat(empty)
    );

    print!(
        "\r{} {} {:>5.1}%",
        spinner,
        progress_bar,
        percent as f64 * 100.0
    );

    let _ = io::stdout().flush();
}



/// Takes a stream opened by a TcpListener and handles incoming packets
fn save_incoming_file(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: TcpStream,
    mut save_path: PathBuf,
    hash: &String
) -> Result<(), String> {

    println!("Waiting on file metadata...");
    let file_metadata = match await_file_metadata(&cipher, nonce, &stream) {
        Ok(output) => output,
        Err(e) => return Err(e)
    };
    println!("File metadata received");
    
    let file_name = file_metadata.0;
    let file_size = file_metadata.1;

    // read file
    save_path.push(&file_name);
    let mut file = match file_rw::open_writable_file(&save_path) {
        Ok(f) => f,
        Err(e) => return Err(e)
    };

    println!("Downloading \"{file_name}\"...");

    // read bytes until peer disconnects
    let mut curr_bytes_read: f64 = 0.0;
    let mut tick = 0;
    let mut last_update = Instant::now();
    let update_interval = Duration::from_millis(100);
    loop {
        let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
        match stream.read_exact(&mut buffer) {
            Ok(_) => (),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof =>  {
                // End connection
                println!("\r✓ [{}]  100.0%", "=".repeat(BAR_WIDTH));
                println!("Peer {} disconnected", stream.peer_addr().unwrap());

                // verify file hash is correct
                if let Err(e) = file.sync_all() {
                    return Err(format!("Failed to ensure all data was written to file: {e}"));
                }

                println!("Verifying file integrity...");
                let hash_bytes = match file_rw::read_file_bytes(&save_path) {
                    Ok(b) => b,
                    Err(e) => return Err(e)
                };
                let computed_file_hash = packet::compute_sha256_hash(&hash_bytes);

                // computed file hash is raw bytes but hash is hexadecimal, so convert hash to 
                // raw bytes to match
                let expected_hash = match hex::decode(hash) {
                    Ok(b) => b,
                    Err(e) => return Err(format!("Failed to decode hash into raw bytes from hex: {e}")),
                };

                if computed_file_hash != expected_hash {
                    return Err(String::from("Failed to verify file hash. File not received correctly."))
                } else {
                    println!("Successfully downloaded \"{file_name}\"");
                }
                return Ok(());
            },
            Err(e) => return Err(format!("Failed to read from stream: {e}"))
        };

        let packet_bytes = match encryption::decrypt_message(nonce, &cipher, &buffer) {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}"))
        };

        let received_packet = match packet::decode_packet(packet_bytes) {
            Ok(p) => p,
            Err(e) => return Err(format!("Unable to decode packet: {e}"))
        };

        let data_bytes: f64 = received_packet.data_length.into();
        curr_bytes_read += data_bytes;
        if let Err(e) = file.write_all(&received_packet.data) {
            return Err(format!("Failed to write byte to file: {e}"))
        }

        // update loading bar if 100ms has elapsed
        if last_update.elapsed() >= update_interval {
            print_loading_bar(curr_bytes_read, file_size, tick);
            tick += 1;
            last_update = Instant::now();
        }
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
    let mut nonce: [u8; 12] = [0; 12];

    // send mode packet
    let req_catalog_packet = packet::encode_packet(String::from("request_file").into_bytes());
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, req_catalog_packet) {
        eprintln!("Failed to send request for sender catalog {e}");
        return;
    }

    println!("Sending file request...");

    // send file hash
    let file_hash_packet = packet::encode_packet(hex::decode(&hash).expect("Unable to decode hexadecimal string"));
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_hash_packet) {
        eprintln!("{e}");
        return;
    }
    println!("File request sent");


    // start receiving file packets, saving it in the directory file_path
    if let Err(e) = save_incoming_file(&cipher, &mut nonce, stream, file_path.clone(), &hash) {
        eprintln!("{e}");
    }
}