//! sender.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! May 16th, 2025
//! CS347 Advanced Software Design

use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::collections::HashMap;
use tokio::runtime::Runtime;
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use x25519_dalek::{EphemeralSecret, PublicKey};
use aes_gcm::{
    aead::{KeyInit, OsRng},
    Aes256Gcm, Key
};
use hex;
use directories::ProjectDirs;
use crate::encryption;
use crate::packet;
use crate::file_rw;

type CatalogMap = HashMap<String, String>; // hash is key, absolute file path is value


/// Gets the path to the catalog. If catalog doesn't exist, a new one is created.
/// The catalog is stored in a static directory. 
/// 
/// The location of static directory depends on the OS:
/// 
/// Linux: `/home/[user]/.local/share/p2p_client`
/// macOS: `/Users/[user]/Library/Application Support/com.LLR.p2p_client`
/// Windows: `C:\Users\[user]\AppData\Roaming\LLR\p2p_client\data`
fn get_catalog_path() -> Result<PathBuf, String> {
    // find existing catalog or create a new one
    let mut catalog_path = match ProjectDirs::from("com", "LLR", "p2p_client") {
        Some(d) => d.data_dir().to_owned().to_path_buf(),
        None => return Err(format!("No valid config directory could be located"))
    };

    if let Err(e) = fs::create_dir_all(&catalog_path) {
        return Err(format!("Failed to create catalog directory: {e}"));
    }

    catalog_path.push("catalog.json");

    Ok(catalog_path)
}


/// Returns catalog as Vector of bytes given the absolute path to it
fn get_serialized_catalog(catalog_path: &PathBuf) -> Result<Vec<u8>, String> {
    if catalog_path.exists() {
        match fs::read(&catalog_path) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(e.to_string()),
        }
    } else {
        // create the file if it doesn't exist
        let empty_catg: CatalogMap = HashMap::new();
        write_updated_catalog(catalog_path, &empty_catg)?;
        match fs::read(&catalog_path) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(e.to_string()),
        }
    }
}


/// Returns catalog as Hashmap given the absolute path to it.
/// If there is no catalog.json file, creates the file and returns an empty Hashmap
fn get_deserialized_catalog(catalog_path: &PathBuf) -> Result<CatalogMap, String> {
    let catalog: CatalogMap;

    if catalog_path.exists() {
        let serialized = match fs::read_to_string(&catalog_path) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };

        let deserialized = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(e) => return Err(e.to_string()),
        };

        catalog = deserialized;
    } else {
        // create the file if it doesn't exist
        let empty_catg: CatalogMap = HashMap::new();
        write_updated_catalog(catalog_path, &empty_catg)?;
        catalog = empty_catg;
    }

    return Ok(catalog)
}


/// Writes changes made to catalog. If there is not file at the given path, will create a file an populate it with a bare json list: {}
fn write_updated_catalog(catalog_path: &PathBuf, catalog: &CatalogMap) -> Result<(), String> {
    // write updated catalog to catalog.json
    let mut json_file = match File::create(catalog_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open catalog file: {e}")),
    };

    let json = match serde_json::to_string_pretty(catalog) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize catalog: {e}")),
    };

    let write_result = json_file.write_all(json.as_bytes());
    if let Err(e) = write_result {
        return Err(format!("Failed to write catalog file: {e}"));
    }

    Ok(())
}


/// Given a file path as input, computes hash of the file, then stores the hash and absolute file path in 
/// catalog.json found in a static directory. See get_catalog_path() for catalog directory locations
pub fn add_file_to_catalog(file_path: &String) -> Result<(), String> {
    let catalog_path = match get_catalog_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive catalog path: {e}"))
    };

    let mut catalog = match get_deserialized_catalog(&catalog_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive catalog: {e}"))
    };

    let absolute_file_path = match fs::canonicalize(&file_path) {
        Ok(p) => p,
        Err(e) => return Err(format!("Unable to get the requested file's absolute path: {e}"))
    };
    
    // get hash of file
    let file_bytes = match file_rw::read_file_bytes(&absolute_file_path) {
        Ok(b) => b,
        Err(e) => return Err(e)
    };
    let file_hash = packet::compute_sha256_hash(&file_bytes);
    let file_hash_string: String = hex::encode(&file_hash);

    // Ruben doesn't think this is the behavior we want. I think we want the value to be updated,
    // otherwise if you want to change the file path you need to call remove, then add
    
    // check if this file is already in catalog
    // checks by hash, not file name, so two files with the same name but different content can coexist
    // if catalog.contains_key(&file_hash_string) {
    //     println!("File {file_path} ({file_hash_string}) already exists in catalog");
    //     return Ok(());
    // }

    // add/update entry in catalog
    catalog.insert(file_hash_string.clone(), absolute_file_path.to_string_lossy().into_owned());

    if let Err(e) = write_updated_catalog(&catalog_path, &catalog) {
        return Err(format!("Error writing updated catalog: {}", e));
    }

    println!("Successfully added {file_path} ({file_hash_string}) to catalog");
    
    Ok(())
}

/// Given a file hash as input, removes the associated entry from the catalog
/// 
/// If the input hash is `DELETE-ALL` then all entries in the catalog will be removed
pub fn remove_file_from_catalog(hash: &String) -> Result<(), String> {
    let catalog_path = match get_catalog_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive catalog path: {e}"))
    };

    let mut catalog = match get_deserialized_catalog(&catalog_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive catalog: {e}"))
    };

    if hash == "DELETE-ALL" {
        catalog.clear();
        println!("Successfully removed all entries from catalog");
    } else {
        match catalog.remove(hash) {
            None => println!("Entry \"{hash}\" does not exist in catalog"),
            Some(f) => {
                let file_name = PathBuf::from(f).file_name().unwrap().to_string_lossy().into_owned();
                println!("Successfully removed {file_name} ({hash}) from catalog")}
        };
    }

    // write updated catalog to catalog.json
    if let Err(e) = write_updated_catalog(&catalog_path, &catalog) {
        return Err(format!("Error writing updated catalog: {}", e));
    }

    Ok(())
}

// Displays the contents of the catalog
pub fn view_catalog() -> Result<(), String> {
    let catalog_path = match get_catalog_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retrieve catalog path: {e}")),
    };

    let catalog = match get_deserialized_catalog(&catalog_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retrieve catalog: {e}")),
    };

    if catalog.is_empty() {
        println!("Catalog is empty.");
        return Ok(());
    }

    // dynamically determine max name length
    let max_name_len = catalog
        .values() // get iterator over the file paths stored in catalog
        // for each path, get the name of the file and its length
        .filter_map(|path| {
            let name = Path::new(path).file_name()?.to_str()?;
            Some(name.len())
        })
        .max() // take the max of those lengths
        .unwrap_or(0); // if the iterator is empty, return 0 instead of None

    // sha256 hashes are 64 characters long
    let hash_len = 64;

    // print table header
    println!(
        "| {:<hash_len$} | {:<width$}",
        "SHA-256 Hash",
        "File Name",
        width = max_name_len
    );

    // 2 gives space for the bar separating hash and path
    println!("|{}|{}", "=".repeat(2 + hash_len), "=".repeat(2 + max_name_len));

    // print each catalog entry
    for (hash, path) in catalog.iter() {
        let file_name = Path::new(path)
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or("invalid UTF-8");

        println!("| {:<hash_len$} | {:<width$}", hash, file_name, width = max_name_len);
    }

    Ok(())
}


/// Returns the absolute file path of a file (from the catalog) given its hash
pub fn get_file_from_catalog(hash: &String) -> Result<PathBuf, String> {

    // load existing catalog or create a new one
    let catalog_path = match get_catalog_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retreive catalog path: {e}"))
    };

    let catalog = match get_deserialized_catalog(&catalog_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retreive catalog: {e}"))
    };

    // get file path from catalog
    let file_name = match catalog.get(hash) {
        Some(f) => f.to_owned(),
        None => return Err(format!("Requested file does not exist in catalog"))
    };
    
    return Ok(PathBuf::from(file_name))
}


/// Send a file name and its hash to the requesting TcpStream
fn send_file_name_and_hash(file_path: &PathBuf, cipher: &Aes256Gcm, mut nonce: &mut [u8; 12], mut stream: &mut TcpStream) -> Result<(), String> {
    
    // send file name
    match file_path.file_name() {
        Some(f) => {
            let file_name_packet = packet::encode_packet(f.to_string_lossy().into_owned().as_bytes().to_vec());
            if let Err(e)  = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_name_packet) {
                return Err(format!("Unable to send file name: {e}"));
            }
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
    if let Err(e) = encryption::send_to_connection(&mut stream, &mut nonce, &cipher, file_hash_packet) {
        return Err(format!("Unable to send hash: {e}"));
    }

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

    // listen for the mode packet sent
    let mut buffer = [0u8; packet::PACKET_SIZE + 16];
    if let Err(e) = stream.read(&mut buffer) {
        eprintln!("Failed to read from stream: {e}");
        return;
    }

    let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&initial_nonce);
    let mode_packet = match encryption::decrypt_message(&nonce, &cipher, &buffer) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to decrypt ciphertext of mode packet: {e}");
            return;
        }
    };
    encryption::increment_nonce(&mut initial_nonce);

    let mode_packet = match packet::decode_packet(mode_packet) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Unable to decode mode packet: {e}");
            return;
        }
    };

    // split tasks depending on mode sent by requester
    match String::from_utf8(mode_packet.data) {
        Ok(m) if m == "request_catalog" => {
            println!("Request catalog mode");
            if let Err(e) = fulfill_catalog_request(&mut stream, &mut initial_nonce, &cipher) {
                eprintln!("Failed to fulfill catalog request: {e}");
            }
        },
        Ok(m) if m == "request_file" => {
            println!("Request file mode");
            if let Err(e) = fulfill_file_request(&mut stream, &mut initial_nonce, &cipher) {
                eprintln!("Failed to fulfill file request: {e}");
            }
        },
        Ok(_) => {},
        Err(e) => {
            eprintln!("Failed to read mode: {e}");
            return
        }
    }
}


/// Handles sending listener's catalog to requester
fn fulfill_catalog_request(stream: &mut TcpStream, initial_nonce: &mut[u8; 12], cipher: &Aes256Gcm) -> Result<(), String> {
    let catalog_path = match get_catalog_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to retrieve catalog path: {e}")),
    };

    let catalog = match get_serialized_catalog(&catalog_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to retrieve catalog: {e}")),
    };

    let message = packet::encode_packet(catalog);
    if let Err(e) = encryption::send_to_connection(stream, initial_nonce, cipher, message) {
        return Err(format!("Failed to send catalog: {e}"));
    }

    Ok(())
}


/// Handles sending requested file to requester
fn fulfill_file_request(mut stream: &mut TcpStream, mut initial_nonce: &mut[u8; 12], cipher: &Aes256Gcm) -> Result<(), String> {
    // listen for hash of file to send
    let mut buffer = [0u8; packet::PACKET_SIZE + 16];
    if let Err(e) = stream.read(&mut buffer) {
        return Err(format!("Failed to read hash from stream: {e}"));
    }
    
    let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(initial_nonce);
    let file_hash_packet = match encryption::decrypt_message(&nonce, cipher, &buffer) {
        Ok(h) => h,
        Err(e) => {
            return Err(format!("Failed to decrypt ciphertext: {e}"));
        }
    };
    encryption::increment_nonce(initial_nonce);

    let file_hash_packet = match packet::decode_packet(file_hash_packet) {
        Ok(p) => p,
        Err(e) => {
            return Err(format!("Unable to decode packet: {e}"));
        }
    };

    // figure out what file was requested
    let file_hash = hex::encode(file_hash_packet.data);
    let file_path = match get_file_from_catalog(&file_hash) {
        Ok(p) => p,
        Err(e) => {
            return Err(format!("Failed to get file from catalog: {e}"));
        }
    };

    // send peer file name and hash to be able to know what to save it as and verify they got it correctly
    if let Err(e) = send_file_name_and_hash(&file_path, &cipher, initial_nonce, stream) {
        return Err(format!("Failed to send file name and hash to peer: {e}"));
    }

    // read file
    let mut file_bytes = match file_rw::open_iterable_file(&file_path) {
        Ok(b) => b,
        Err(e) => {
            return Err(format!("Unable to open file: {e}"));
        }
    };

    println!("Beginning to send {:?} to {:?}...", file_path.file_name().unwrap(), stream.peer_addr().unwrap());

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
                    if let Err(e) = encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, message) { 
                        return Err(format!("Failed to send packet: {e}"));
                    }
                    println!("File {:?} successfully sent to {:?}", file_path.file_name().unwrap(), stream.peer_addr().unwrap());
                    return Ok(());
                }
            }
        }
        // encode the data and send the packet
        let message = packet::encode_packet(write_bytes);
        if let Err(e) = encryption::send_to_connection(&mut stream, &mut initial_nonce, &cipher, message) {
            return Err(format!("{e}"));
        }
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