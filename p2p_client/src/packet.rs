use std::mem;
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};

// packets are always 512 bytes long 
struct Packet {
    data_length: u16,
    filename_len: u16,
    filename: String,
    data: Vec<u8>,
    chunk_hash: [u8; 32],
    file_hash: [u8; 32],
}

/// extract data from packet and verify integrity
pub fn decode_packet(packet_bytes: [u8; 512]) -> Packet {
    let mut packet: Packet;
    let mut offset = 0;

    // convert data length bytes into u16
    let value = BigEndian::read_u16(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    packet.data_length = value;
    offset += mem::size_of::<u16>();
    
    // 
    


}

/// wrap data
// unsure that data should be type Vec
pub fn encode_packet(filename: String, data: Vec<u8>, file_hash: [u8; 32]) -> [u8; 512] {
    // initialize packet array and offset
    let mut packet: [u8; 512] = [0; 512];
    let mut offset = 0;
    
    // append data length
    let data_length = (data.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&data_length);
    offset += mem::size_of::<u16>();

    // append filename length
    let filename_len = (filename.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&filename_len);
    offset += mem::size_of::<u16>();

    // append filename
    let filename = filename.as_bytes();
    packet[offset..offset + filename.len()].copy_from_slice(filename);
    offset += filename.len();

    // append data
    packet[offset..offset + data.len()].copy_from_slice(&data);
    offset += data.len();

    // append hash of chunk
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&data[..]);
    // read hash digest and consume hasher
    let chunk_hash = hasher.finalize();
    let chunk_hash_len = chunk_hash.len();
    packet[offset..offset + chunk_hash_len].copy_from_slice(&chunk_hash);
    offset += chunk_hash_len;

    // append hash of file
    packet[offset..offset + file_hash.len()].copy_from_slice(&file_hash);
    
    return packet;
}