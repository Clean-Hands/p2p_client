use std::mem;
use sha256::{digest, try_digest};

// packets are always 512 bytes long 
struct Packet {
    data_length: u16,
    filename_len: u16,
    filename: &str,
    data: Vec<u8>,
    chunk_hash: [u8; 32],
    file_hash: [u8; 32],
}

impl Packet {
    /// extract data from packet and verify integrity
    fn decode_packet(&self) -> Packet {

    }
}

/// wrap data
// unsure that data should be type Vec
fn encode_packet(filename: String, data: Vec<u8>) -> [u8; 512] {
    // initialize packet array and offset
    let packet: [u8; 512];
    let offset = 0;
    
    // append data_length
    let data_length = (data.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&data_length);
    offset += mem::size_of::<u16>();

    //

}

fn main() {
    // initialize packet array and offset
    let data: Vec<u8> = vec![1, 2, 3, 4];
    let mut packet = [7u8; 10];
    let mut offset = 0;
    
    // append data_length
    let data_length = (data.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&data_length);
    offset += mem::size_of::<u16>();

    println!("{:?}", packet);
}