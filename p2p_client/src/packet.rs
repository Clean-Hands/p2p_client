//! packet.rs
//! by Ruben Boero, Liam Keane
//! April 25th, 2025
//! CS347 Advanced Software Design

use std::mem;
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};


/// Packet struct to contain relevant items of our packet protocol 
/// 
/// packets are always 512 bytes long (padded with 0s as needed)
/// 
/// data length: the sum of all bytes in packet EXCEPT padding bytes
/// 
/// chunk_hash: sha256 chunk hash computed over data_length, filename_len, filename, and data fields
/// 
/// file_hash: sha256 file hash computed over the entire contents of the file that is being sent
#[derive(Default, Debug, PartialEq)]
pub struct Packet {
    pub data_length: u16,
    pub filename_len: u16,
    pub filename: String,
    pub data: Vec<u8>,
    pub chunk_hash: [u8; 32],
    pub file_hash: [u8; 32],
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

/// extract data from packet and verify integrity via hash
/// 
/// returns Result type that contains Err if the chunk hash verification fails, and the created 
/// Packet struct otherwise
pub fn decode_packet(packet_bytes: [u8; 512]) -> Result<Packet, String> {
    let mut packet: Packet = Packet{..Default::default()};
    let mut chunk_to_hash: Vec<u8> = vec![];
    let mut offset = 0;

    // convert data length bytes into u16
    let data_len = BigEndian::read_u16(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    packet.data_length = data_len;
    chunk_to_hash.extend_from_slice(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    offset += mem::size_of::<u16>();
    
    // convert filename length bytes into u16
    let filename_len = BigEndian::read_u16(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    packet.filename_len = filename_len;
    chunk_to_hash.extend_from_slice(&packet_bytes[offset..offset + mem::size_of::<u16>()]);
    offset += mem::size_of::<u16>();

    // read filename, add it to struct
    let filename = String::from_utf8_lossy(&packet_bytes[offset..offset + (filename_len as usize)]);
    packet.filename = filename.to_string();
    chunk_to_hash.extend_from_slice(&packet_bytes[offset..offset + (filename_len as usize)]);
    offset += filename_len as usize;

    // compute the length of file data
    let file_data_len = data_len - 
                    (mem::size_of::<u16>() as u16)*2 -  // subtract data and filename lengths
                    filename_len - 
                    (mem::size_of::<u8>() as u16)*32*2; // subtract length of two sha256 hashes

    // add file data 
    packet.data = packet_bytes[offset..offset + (file_data_len as usize)].to_vec();
    chunk_to_hash.extend_from_slice(&packet_bytes[offset..offset + (file_data_len as usize)]);
    offset += file_data_len as usize;

    // add chunk hash
    let mut chunk_hash_arr: [u8; 32] = [0; 32];
    chunk_hash_arr.copy_from_slice(&packet_bytes[offset..offset + 32]);
    packet.chunk_hash = chunk_hash_arr;
    offset += mem::size_of::<u8>()*32; // 32 is len of sha256 hash

    let chunk_hash = compute_sha256_hash(chunk_to_hash);
    
    if chunk_hash != packet.chunk_hash {
        return Err("Computed chunk hash does not match chunk hash within packet.".to_string());
    }

    // add file hash
    let mut file_hash_arr: [u8; 32] = [0; 32];
    file_hash_arr.copy_from_slice(&packet_bytes[offset..offset + 32]);
    packet.file_hash = file_hash_arr;

    Ok(packet) // return the completed packet
}

/// wrap data in our packet protocol
/// 
/// input filename: name of the file that is being sent
/// 
/// input data: bytes that represent the chunk of the file being sent
/// 
/// input file_hash: sha256 hash of the entire file being sent
/// 
/// output: array of bytes to send
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
    hash_vec.extend_from_slice(&data_length_bytes);
    offset += mem::size_of::<u16>();
    
    // append filename length
    let filename_len = (filename.len() as u16).to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&filename_len);
    hash_vec.extend_from_slice(&filename_len);
    offset += mem::size_of::<u16>();

    // append filename
    let filename = filename.as_bytes();
    packet[offset..offset + filename.len()].copy_from_slice(filename);
    hash_vec.extend_from_slice(&filename);
    offset += filename.len();
    
    // append data
    packet[offset..offset + data.len()].copy_from_slice(&data);
    hash_vec.extend_from_slice(&data);
    offset += data.len();
    
    // compute and append chunk hash
    let chunk_hash = compute_sha256_hash(hash_vec);
    packet[offset..offset + chunk_hash.len()].copy_from_slice(&chunk_hash);
    offset += chunk_hash.len();

    // append file hash of file
    packet[offset..offset + file_hash.len()].copy_from_slice(&file_hash);
    
    return packet;
}

#[cfg(test)]
// TODO: these tests aren't amazing since they assume that the output from functions are correct. 
// The output is then hard coded in the tests. Not sure of better way to fix them. 
mod tests {
    // use super::*;
    // why can i not use super like in line above?
    use crate::packet::{self, Packet};

    #[test]
    fn test_encode_packet() {
        let filename = String::from("test.txt");
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let file_hash: [u8; 32] = [7; 32];
        let actual: [u8; 512] = packet::encode_packet(filename, data, file_hash);
        let expected: [u8; 512] = [0, 87, 0, 8, 116, 101, 115, 116, 46, 116, 120, 116, 1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 225, 12, 171, 217, 101, 208, 53, 140, 202, 193, 162, 185, 202, 9, 198, 105, 184, 61, 132, 233, 44, 148, 213, 111, 38, 87, 245, 175, 76, 14, 186, 117, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; 
        
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decode_packet() {
        let expected = Packet {
            data_length: 87, 
            filename_len: 8, 
            filename: String::from("test.txt"),
            data: vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1],
            chunk_hash: [225, 12, 171, 217, 101, 208, 53, 140, 202, 193, 162, 185, 202, 9, 198, 105, 184, 61, 132, 233, 44, 148, 213, 111, 38, 87, 245, 175, 76, 14, 186, 117],
            file_hash: [7; 32],
        };

        let filename = String::from("test.txt");
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let file_hash: [u8; 32] = [7; 32];
        let packet: [u8; 512] = packet::encode_packet(filename, data, file_hash);
        let actual = packet::decode_packet(packet);

        // need to wrap expected in Ok so that it matches the actual output, which hopefully is also Ok
        assert_eq!(actual, Ok(expected));
    }

    

    // I wasn't convinced that the PartialEq that rust autogenerated for Packet struct would be correct
    #[test]
    fn test_unequal_packets() {
        let expected = Packet {
            data_length: 87,
            filename_len: 8, 
            filename: String::from("different packet.txt"), //  name is different, so packets should be unequal
            data: vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1],
            chunk_hash: [225, 12, 171, 217, 101, 208, 53, 140, 202, 193, 162, 185, 202, 9, 198, 105, 184, 61, 132, 233, 44, 148, 213, 111, 38, 87, 245, 175, 76, 14, 186, 117],
            file_hash: [7; 32],
        };

        let filename = String::from("test.txt");
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let file_hash: [u8; 32] = [7; 32];
        let packet: [u8; 512] = packet::encode_packet(filename, data, file_hash);
        let actual = packet::decode_packet(packet);

        assert_ne!(actual, Ok(expected));
    }

    #[test]
    fn test_hash_check_failure() {
        let filename = String::from("test.txt");
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let file_hash: [u8; 32] = [7; 32];
        let mut packet: [u8; 512] = packet::encode_packet(filename, data, file_hash);

        let chunk_hash_start = 2 + 2 + 8 + 11; // header + filename + data
        packet[chunk_hash_start] ^= 0xFF; // flip bits of chunk hash to cause error (using XOR)
        let actual = packet::decode_packet(packet);
        
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err(), "Computed chunk hash does not match chunk hash within packet.");
    }
}