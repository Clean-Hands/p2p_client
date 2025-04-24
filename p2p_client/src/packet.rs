// packet.rs
// by Ruben Boero, Liam Keane
// April 24th, 2025
// CS347 Advanced Software Design

use std::mem;
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};

// packets are always 512 bytes long 
#[derive(Default, Debug)]
pub struct Packet {
    data_length: u16,   // the sum of all bytes in packet EXCEPT padding bytes
    filename_len: u16,
    filename: String,
    data: Vec<u8>,
    chunk_hash: [u8; 32],   // chunk hash computed over data_length, filename_len, filename, and data fields
    file_hash: [u8; 32],    // using sha256 hashes always results in 32 bytes
}

/// given a vector of bytes, compute and return the sha256 hash
fn compute_sha256_hash(data: Vec<u8>) -> [u8; 32]{
    let mut hasher = Sha256::new();
    hasher.update(&data[..]);

    // read hash digest and consume hasher
    let chunk_hash = hasher.finalize();
    let mut output: [u8; 32] = [0; 32];
    output.copy_from_slice(&chunk_hash);

    output  // return hash
}

/// extract data from packet and verify integrity
pub fn decode_packet(packet_bytes: [u8; 512]) -> Packet {
    let mut packet: Packet = Packet{..Default::default()};
    let mut offset = 0;

    // convert data length bytes into u16
    let data_len = BigEndian::read_u16(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    println!("DATA LEN: {data_len}");
    packet.data_length = data_len;
    offset += mem::size_of::<u16>();
    
    // convert filename length bytes into u16
    let filename_len = BigEndian::read_u16(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    packet.filename_len = filename_len;
    offset += mem::size_of::<u16>();

    // read filename, add it to struct
    let filename = String::from_utf8_lossy(&packet_bytes[offset..offset + (filename_len as usize)]);
    packet.filename = filename.to_string();
    offset += filename_len as usize;

    // compute the length of file data
    let file_data_len = data_len - 
                    (mem::size_of::<u16>() as u16)*2 -  // subtract data and filename lengths
                    filename_len - 
                    (mem::size_of::<u8>() as u16)*32*2; // subtract length of two sha256 hashes

    // add file data 
    packet.data = packet_bytes[offset..offset + (file_data_len as usize)].to_vec();
    offset += file_data_len as usize;

    // add chunk hash
    let mut chunk_hash_arr: [u8; 32] = [0; 32];
    chunk_hash_arr.copy_from_slice(&packet_bytes[offset..offset + 32]);
    packet.chunk_hash = chunk_hash_arr;
    offset += mem::size_of::<u8>()*32; // 32 is len of sha256 hash

    
    // assert_eq!();

    // add file hash
    let mut file_hash_arr: [u8; 32] = [0; 32];
    file_hash_arr.copy_from_slice(&packet_bytes[offset..offset + 32]);
    packet.file_hash = file_hash_arr;

    packet // return the completed packet

}

/// wrap data
// ensure that data should be type Vec
pub fn encode_packet(filename: String, data: Vec<u8>, file_hash: [u8; 32]) -> [u8; 512] {
    // initialize packet array and offset
    let mut packet: [u8; 512] = [0; 512];
    let mut offset = 0;
    let mut hash_vec: Vec<u8> = vec![];
    
    // append data length
    let data_length: u16 = (mem::size_of::<u16>()*2 +
                                filename.len() +
                                (data.len() as usize) + 
                                (mem::size_of::<u8>() as usize)*32*2) as u16;
    let data_length_bytes: [u8; 2] = data_length.to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&data_length_bytes);
    offset += mem::size_of::<u16>();
    hash_vec.extend_from_slice(&data_length_bytes);

    // append filename length
    let filename_len = (filename.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&filename_len);
    offset += mem::size_of::<u16>();
    hash_vec.extend_from_slice(&filename_len);

    // append filename
    let filename = filename.as_bytes();
    packet[offset..offset + filename.len()].copy_from_slice(filename);
    offset += filename.len();
    hash_vec.extend_from_slice(&filename);

    // append data
    packet[offset..offset + data.len()].copy_from_slice(&data);
    offset += data_length as usize;
    hash_vec.extend_from_slice(&data);

    // compute and append chunk hash
    let chunk_hash = compute_sha256_hash(hash_vec);
    packet[offset..offset + chunk_hash.len()].copy_from_slice(&chunk_hash);
    offset += chunk_hash.len();

    // append file hash of file
    packet[offset..offset + file_hash.len()].copy_from_slice(&file_hash);
    
    return packet;
}