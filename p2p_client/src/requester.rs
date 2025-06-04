//! requester.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! June 4th, 2025
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
use serde::{Deserialize, Serialize};
use size::Size;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, ErrorKind, Read, Write},
    net::TcpStream,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    thread::sleep,
    time::{Duration, Instant},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

type PeerMap = HashMap<String, String>;
type CatalogMap = HashMap<String, FileInfo>;

#[derive(Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct FileInfo {
    file_path: String,
    file_size: u64,
}

const SPINNER: &[char] = &['|', '/', '-', '\\'];
const BAR_WIDTH: usize = 50;
const UPDATE_DELAY_MS: u64 = 100;

const PING_TIMEOUT: u64 = 1;



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
        None => return Err(format!("No valid config directory could be located")),
    };

    if let Err(e) = fs::create_dir_all(&peer_list_path) {
        return Err(format!("Failed to create peers directory: {e}"));
    }

    peer_list_path.push("peers.json");

    Ok(peer_list_path)
}



/// Returns peer list as Hashmap given the absolute path to it
/// If there is no peers.json file, creates the file and returns an empty Hashmap
fn get_deserialized_peer_list(peer_list_path: &PathBuf) -> Result<PeerMap, String> {
    let peer_list: PeerMap;

    if peer_list_path.exists() {
        let serialized = match fs::read_to_string(&peer_list_path) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };

        let deserialized = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(e) => return Err(e.to_string()),
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



/// Writes changes made to peer_list. If there is not file at the given path, it will create a file and
/// populate it with a bare json list: {}
fn write_updated_peer_list(peer_list_path: &PathBuf, peer_list: &PeerMap) -> Result<(), String> {
    // write updated peer list to peers.json
    let mut json_file = match File::create(peer_list_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open peer list file: {e}")),
    };

    let json = match serde_json::to_string_pretty(peer_list) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize peer list: {e}")),
    };

    let write_result = json_file.write_all(json.as_bytes());
    if let Err(e) = write_result {
        return Err(format!("Failed to write peer list file: {e}"));
    }

    Ok(())
}



/// Given an IP and alias for the IP as input, stores them in peers.json
/// found in a static directory. See get_peer_list_path() for peers.json locations
pub fn add_ip_to_peers(alias: &String, peer_addr: &String) -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive peer list path: {e}")),
    };

    let mut peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive peer list: {e}")),
    };

    // add/update entry in peer_list
    peer_list.insert(alias.clone(), peer_addr.clone());

    if let Err(e) = write_updated_peer_list(&peer_list_path, &peer_list) {
        return Err(format!("Error writing updated catalog: {}", e));
    }

    println!("Successfully added {alias} ({peer_addr}) to peer list");

    Ok(())
}



/// Given an alias as input, removes the associated entry from the peer list
///
/// If the input alias is `DELETE-ALL` then all entries in the catalog will be removed
pub fn remove_ip_from_peer_list(alias: &String) -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive peer list path: {e}")),
    };

    let mut peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive peer list: {e}")),
    };

    if alias == "DELETE-ALL" {
        peer_list.clear();
        println!("Successfully removed all entries from peer list");
    } else {
        match peer_list.remove(alias) {
            None => println!("Entry \"{alias}\" does not exist in catalog"),
            Some(f) => {
                let peer_addr = String::from(f);
                println!("Successfully removed {alias} ({peer_addr}) from catalog")
            }
        };
    }

    // write updated catalog to catalog.json
    if let Err(e) = write_updated_peer_list(&peer_list_path, &peer_list) {
        return Err(format!("Error writing updated catalog: {e}"));
    }

    Ok(())
}



/// Displays the contents of the peer list
pub fn view_peer_list() -> Result<(), String> {
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retrieve peer list path: {e}")),
    };

    let peer_list = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retrieve peer list: {e}")),
    };

    if peer_list.is_empty() {
        println!("Peer list is empty.");
        return Ok(());
    }

    let max_alias_len = peer_list
        .keys()
        .map(|alias| alias.len())
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"Alias".len())
        .max()
        .unwrap_or("Alias".len());

    let max_ip_len = peer_list
        .values()
        .map(|ip| ip.len())
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"IP Address".len())
        .max()
        .unwrap_or("IP Address".len());

    // print table header
    println!(
        "| {:<max_alias_len$} | {:<width$}",
        "Alias",
        "IP Address",
        width = max_alias_len
    );

    // 2 gives space for the bar separating IP and alias
    println!(
        "|{}|{}",
        "=".repeat(2 + max_alias_len),
        "=".repeat(2 + max_ip_len)
    );

    // print each catalog entry
    for (alias, ip) in peer_list.iter() {
        println!("| {:<max_alias_len$} | {:<max_ip_len$}", alias, ip);
    }

    Ok(())
}



/// Ping an address to check that it is online. If TCP stream is established, stream is closed,
/// and Ok is returned. If TCP stream is not established, Err is returned.
///
/// `peer` can be the IP of the sender or an alias associated with an IP in the peer list
pub fn ping_addr(peer: &String) -> Result<String, String> {
    let addr = match resolve_input(&peer) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };
    let send_addr = format!("{addr}:7878");

    // We only ever ping 1 IP at a time, so treat the vector as a single item
    let socket_addr = match send_addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => return Err(format!("Could not resolve address: {send_addr}")),
        },
        Err(e) => return Err(format!("Failed to resolve address {send_addr}: {e}")),
    };

    // If the peer does not respond in 1 second, we will return Err
    let timeout = Duration::from_secs(PING_TIMEOUT);

    match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(_) => return Ok(format!("{addr} is online!")),
        Err(_) => return Err(format!("{addr} did not respond to ping in time")),
    }
}



/// Takes an opened TcpStream and performs the requester side of the Diffie-Hellman handshake
fn perform_dh_handshake(mut stream: &TcpStream) -> Result<Aes256Gcm, String> {
    // generate DH exchange info
    let local_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
    let local_public_key = PublicKey::from(&local_private_key);

    // read public key from peer
    let mut peer_public_key_bytes: [u8; 32] = [0; 32];
    stream
        .read_exact(&mut peer_public_key_bytes)
        .expect("Failed to read peer's public key");
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
                // println!("Connected to {send_addr}");
                return s;
            }
            Err(e) => {
                eprintln!("Failed to connect to {send_addr}: {e}");
                sleep(Duration::from_secs(1));
            }
        };
    }
}



/// Requests catalog from an alias associated with a peer's IP in the peer list, or given a
/// peer's IP address directly, then prints the contents of the catalog to stdout
pub fn request_catalog(peer: &String) -> Result<(), String> {
    let addr = match resolve_input(&peer) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };

    let mut stream = connect_stream(&addr);

    let cipher = match perform_dh_handshake(&stream) {
        Ok(c) => c,
        Err(e) => return Err(format!("Diffie-Hellman handshake failed: {e}")),
    };

    // send mode packet
    let mut nonce: [u8; 12] = [0; 12];
    let req_catalog_packet = packet::encode_packet(String::from("request_catalog").into_bytes());
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, req_catalog_packet) {
        return Err(format!("Failed to send request for peer's catalog {e}"));
    }

    // listen for response
    let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
    let mut catalog_bytes = Vec::new();
    loop {
        match stream.read_exact(&mut buffer) {
            Ok(_) => {
                let decrypted = match encryption::decrypt_message(&mut nonce, &cipher, &buffer) {
                    Ok(p) => p,
                    Err(e) => return Err(format!("Failed to decrypt packet: {e}")),
                };

                let packet = match packet::decode_packet(decrypted) {
                    Ok(p) => p,
                    Err(e) => return Err(format!("Failed to decode packet: {e}")),
                };

                catalog_bytes.extend_from_slice(&packet.data);
            }
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("Error reading from stream: {e}")),
        }
    }

    // print catalog
    let catalog_json = match String::from_utf8(catalog_bytes) {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to parse catalog as UTF-8: {e}")),
    };

    let catalog: CatalogMap = match serde_json::from_str(&catalog_json) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to deserialize catalog into hash map: {e}")),
    };

    if catalog.is_empty() {
        println!("Peer's catalog is empty.");
        return Ok(());
    }

    // dynamically determine max len name
    let max_name_len = catalog
        .values() // get iterator over the file paths stored in catalog
        // get the length of each file path
        .map(|info| info.file_path.len())
        // make sure that we don't go under the length of the table header
        .filter(|length| length > &"File Name".len())
        .max()
        .unwrap_or("File Name".len());

    // dynamically determine max size length
    let max_size_len = catalog
        .values()
        .map(|info| Size::from_bytes(info.file_size).to_string().len())
        .filter(|length| length > &"Size".len())
        .max()
        .unwrap_or("Size".len());

    let hash_len = 64;

    // print table header
    println!(
        "| {:<hash_len$} | {:<max_name_len$} | {:<max_size_len$}",
        "SHA-256 Hash", "File Name", "Size"
    );

    // 2 gives space for the bars separating columns
    println!(
        "|{}|{}|{}",
        "=".repeat(2 + hash_len),
        "=".repeat(2 + max_name_len),
        "=".repeat(2 + max_size_len)
    );

    // print each catalog entry
    for (hash, info) in catalog.iter() {
        let file_size = Size::from_bytes(info.file_size).to_string();

        println!(
            "| {:<hash_len$} | {:<max_name_len$} | {:<max_size_len$}",
            hash, info.file_path, file_size
        );
    }

    Ok(())
}



/// Receives file name and its size from the sender
fn await_file_metadata(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: &TcpStream,
) -> Result<(String, u64), String> {
    // listen for file name
    let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
    if let Err(e) = stream.read_exact(&mut buffer) {
        return Err(format!("Failed to read from stream: {e}"));
    }
    let file_path = match encryption::decrypt_message(nonce, &cipher, &buffer) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}")),
    };
    let file_path_packet = match packet::decode_packet(file_path) {
        Ok(p) => p,
        Err(e) => return Err(format!("Unable to decode packet: {e}")),
    };
    let file_path = String::from_utf8_lossy(file_path_packet.data.as_slice());

    // listen for the file size
    if let Err(e) = stream.read_exact(&mut buffer) {
        return Err(format!("Failed to read from stream: {e}"));
    }
    let packet_bytes = match encryption::decrypt_message(nonce, &cipher, &buffer) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}")),
    };
    let file_size_packet = match packet::decode_packet(packet_bytes) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to decode packet: {e}")),
    };
    let file_size_array: [u8; 8] = file_size_packet.data
        .try_into()
        .expect("Vec must have exactly 8 elements");
    let file_size = u64::from_be_bytes(file_size_array);

    Ok((String::from(file_path), file_size))
}



/// Prints a download progress bar to stdout
fn print_loading_bar(bytes_sent: u64, total_bytes: u64, bytes_per_sec: u64, tick: usize) {
    let percent: f64 = bytes_sent as f64 / total_bytes as f64;
    let filled = ((percent * BAR_WIDTH as f64).round() as usize).clamp(0, BAR_WIDTH);
    let empty = BAR_WIDTH - filled;
    let spinner = SPINNER[tick % SPINNER.len()];

    let progress_bar = format!("[{}{}]", "=".repeat(filled), " ".repeat(empty));

    print!(
        "\r{} {:>8}/s {} {:>5.1}% {:>10}/{}", // format the percent right-defined, field width of 5 characters, and show one decimal place
        spinner,
        Size::from_bytes(bytes_per_sec).to_string(),
        progress_bar,
        (percent * 100.0).clamp(0.0, 100.0),
        Size::from_bytes(bytes_sent).to_string(),
        Size::from_bytes(total_bytes)
    );

    let _ = io::stdout().flush();
}



/// Takes a stream opened by a TcpListener and handles incoming packets
fn save_incoming_file(
    cipher: &Aes256Gcm,
    nonce: &mut [u8; 12],
    mut stream: TcpStream,
    mut save_path: PathBuf,
    hash: &String,
) -> Result<(), String> {
    let file_metadata = match await_file_metadata(&cipher, nonce, &stream) {
        Ok(output) => output,
        Err(e) => return Err(e),
    };

    let file_name = file_metadata.0;
    let file_size = file_metadata.1;

    // read file
    save_path.push(&file_name);
    let mut file = match file_rw::open_writable_file(&save_path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    println!("Downloading \"{file_name}\"...");

    // read bytes until peer disconnects
    let mut curr_bytes_read: u64 = 0;
    let mut tick = 0;
    let mut last_update = Instant::now();
    let update_interval = Duration::from_millis(UPDATE_DELAY_MS);
    let mut bytes_per_sec: u64 = 0;
    loop {
        let mut buffer = [0u8; packet::PACKET_SIZE + encryption::AES256GCM_VER_TAG_SIZE];
        match stream.read_exact(&mut buffer) {
            Ok(_) => (),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                // End connection
                println!("\r✓ [{}] 100.0% {}", "=".repeat(BAR_WIDTH), " ".repeat(35));

                // verify file hash is correct
                if let Err(e) = file.sync_all() {
                    return Err(format!(
                        "Failed to ensure all data was written to file: {e}"
                    ));
                }

                // for big files where hashing takes forever, this helps the user understand
                // what is going on when the program says 100% but is still working
                println!("Verifying file hash...");

                let hash_bytes = match file_rw::read_file_bytes(&save_path) {
                    Ok(b) => b,
                    Err(e) => return Err(e),
                };
                let computed_file_hash = packet::compute_sha256_hash(&hash_bytes);

                // computed file hash is raw bytes but hash is hexadecimal, so convert hash to raw bytes to match
                let expected_hash = match hex::decode(hash) {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(format!("Failed to decode hash into raw bytes from hex: {e}"));
                    }
                };

                if computed_file_hash != expected_hash {
                    return Err(String::from(
                        "Failed to verify file hash. File not received correctly.",
                    ));
                } else {
                    println!("Successfully downloaded \"{file_name}\"");
                }

                return Ok(());
            }
            Err(e) => return Err(format!("Failed to read from stream: {e}")),
        };

        let packet_bytes = match encryption::decrypt_message(nonce, &cipher, &buffer) {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to decrypt ciphertext: {e}")),
        };

        let received_packet = match packet::decode_packet(packet_bytes) {
            Ok(p) => p,
            Err(e) => return Err(format!("Unable to decode packet: {e}")),
        };

        let data_bytes_delta: u64 = received_packet.data_length.try_into().unwrap();
        curr_bytes_read += data_bytes_delta;
        if let Err(e) = file.write_all(&received_packet.data) {
            return Err(format!("Failed to write byte to file: {e}"));
        }

        bytes_per_sec += data_bytes_delta;

        // update loading bar if UPDATE_DELAY_MS has elapsed
        if last_update.elapsed() >= update_interval {
            bytes_per_sec *= 1000 / UPDATE_DELAY_MS;
            print_loading_bar(curr_bytes_read, file_size, bytes_per_sec, tick);
            tick += 1;
            bytes_per_sec = 0;
            last_update = Instant::now();
        }
    }
}



/// Returns the IP associated with the given alias (from the peer catalog)
fn get_ip_from_peer_list(alias: &String) -> Result<String, String> {
    // load existing catalog or create a new one
    let peer_list_path = match get_peer_list_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive peer list path: {e}")),
    };

    let catalog = match get_deserialized_peer_list(&peer_list_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive peer list: {e}")),
    };

    // get IP from peer list
    let ip = match catalog.get(alias) {
        Some(i) => i.to_owned(),
        None => return Err(format!("Requested alias does not exist in catalog")),
    };

    Ok(ip)
}



/// Takes in a peer (either alias or IP address) and returns an IP address
fn resolve_input(peer: &String) -> Result<String, String> {
    if let Ok(ip) = peer.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    match get_ip_from_peer_list(&peer) {
        Ok(a) => Ok(a),
        Err(e) => return Err(format!("Failed to retrieve IP associated with {peer}: {e}")),
    }
}



/// Send a request for a file by its `hash` to the `peer`, saving it in `file_path`.
///
/// `peer` can be an IP or an alias saved in the peer list associated with an IP.
pub fn request_file(peer: String, hash: String, file_path: PathBuf) {
    // determine if user input an alias or an IP
    let addr = match resolve_input(&peer) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let mut stream = connect_stream(&addr);

    let cipher = match perform_dh_handshake(&stream) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Diffie-Hellman handshake failed: {e}");
            return;
        }
    };
    
    // send mode packet
    let req_catalog_packet = packet::encode_packet(String::from("request_file").into_bytes());
    let mut nonce: [u8; 12] = [0; 12];
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, req_catalog_packet) {
        eprintln!("Failed to send request for sender catalog {e}");
        return;
    }

    // send file hash
    let file_hash_packet = packet::encode_packet(hex::decode(&hash)
        .expect("Unable to decode hexadecimal string"));
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_hash_packet) {
        eprintln!("{e}");
        return;
    }

    // start receiving file packets, saving it in the directory file_path
    if let Err(e) = save_incoming_file(&cipher, &mut nonce, stream, file_path.clone(), &hash) {
        eprintln!("{e}");
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener;
    use serial_test::serial;
    use std::{fs, net::TcpListener};
    use tokio::runtime::Runtime;

    #[test]
    fn test_peer_list_workflow() {
        let list_path = get_peer_list_path().unwrap();

        let backup_path = list_path.with_file_name("peers.json.backup");

        let had_existing = if list_path.exists() {
            fs::rename(&list_path, &backup_path).is_ok()
        } else {
            false
        };

        // add items to a peer list
        let map = PeerMap::new();
        let write_result = write_updated_peer_list(&list_path, &map);
        assert!(write_result.is_ok());

        assert!(add_ip_to_peers(&String::from("alice"), &String::from("10.0.0.1")).is_ok());
        assert!(add_ip_to_peers(&String::from("bob"), &String::from("10.0.0.2")).is_ok());

        // verify add was completed correctly
        let read_result = get_deserialized_peer_list(&list_path);
        assert!(read_result.is_ok());

        let read_result = read_result.unwrap();
        assert_eq!(read_result.len(), 2);
        assert_eq!(read_result.get("alice"), Some(&"10.0.0.1".to_string()));
        assert_eq!(read_result.get("bob"), Some(&"10.0.0.2".to_string()));

        // remove a peer
        assert!(remove_ip_from_peer_list(&String::from("alice")).is_ok());

        // check final state is correct
        let final_read = get_deserialized_peer_list(&list_path).unwrap();
        assert_eq!(final_read.len(), 1);
        assert!(!final_read.contains_key("alice"));
        assert!(final_read.contains_key("bob"));

        // cleanup
        if let Err(e) = fs::remove_file(&list_path) {
            eprintln!("Failed to remove testing file: {e}");
        }

        if had_existing {
            let _ = fs::rename(&backup_path, &list_path);
        }
    }

    async fn listen_for_one_connection() {
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
    fn test_pinging_online_peer() {
        // start listener
        let runtime = Runtime::new().expect("Failed to create a runtime");
        let _ = runtime.enter();
        runtime.spawn(listen_for_one_connection());

        let result = ping_addr(&"127.0.0.1".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinging_offline_peer() {
        let result = ping_addr(&"127.0.0.1".to_string());
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    // TODO: Lazuli changed request_catalog to return a String instead of printing to stdout in gui branch
    // When they merge the gui branch into main, compare the returned String with an expected string
    fn test_catalog_request() {
        // start listener
        let runtime = Runtime::new().expect("Failed to create a runtime");
        let _ = runtime.enter();
        runtime.spawn(listen_for_one_connection());

        let result = request_catalog(&"127.0.0.1".to_string());
        assert!(result.is_ok());
    }
}
