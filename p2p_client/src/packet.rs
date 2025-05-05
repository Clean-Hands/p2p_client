//! packet.rs
//! by Ruben Boero, Liam Keane, Lazuli Kleinhans
//! April 29th, 2025
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
/// chunk_hash: sha256 chunk hash computed over data_length and data fields
#[derive(Default, Debug, PartialEq)]
pub struct Packet {
    pub data_length: u16,
    pub data: Vec<u8>, // up to 478 bytes
    pub chunk_hash: [u8; 32],
}

/// given a vector of bytes, compute and return the sha256 hash 
pub fn compute_sha256_hash(data: &Vec<u8>) -> [u8; 32]{
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

    // compute the length of file data
    let file_data_len = data_len - 
                    mem::size_of::<u16>() as u16 -  // subtract data length
                    mem::size_of::<u8>() as u16*32; // subtract length of sha256 hash

    // add file data 
    packet.data = packet_bytes[offset..offset + (file_data_len as usize)].to_vec();
    chunk_to_hash.extend_from_slice(&packet_bytes[offset..offset + (file_data_len as usize)]);
    offset += file_data_len as usize;

    // add chunk hash
    let mut chunk_hash_arr: [u8; 32] = [0; 32];
    chunk_hash_arr.copy_from_slice(&packet_bytes[offset..offset + 32]);
    packet.chunk_hash = chunk_hash_arr;

    let chunk_hash = compute_sha256_hash(&chunk_to_hash);
    
    if chunk_hash != packet.chunk_hash {
        return Err("Computed chunk hash does not match chunk hash within packet.".to_string());
    }

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
pub fn encode_packet(data: Vec<u8>) -> [u8; 512] {
    // initialize packet array and offset
    let mut packet: [u8; 512] = [0; 512];
    let mut offset = 0;
    let mut hash_vec: Vec<u8> = vec![];
    
    // append data length
    let data_length: u16 = (mem::size_of::<u16>() +
                                data.len() as usize + 
                                (mem::size_of::<u8>() as usize)*32) as u16;
    let data_length_bytes: [u8; 2] = data_length.to_be_bytes();
    packet[offset..offset + mem::size_of::<u16>()].copy_from_slice(&data_length_bytes);
    hash_vec.extend_from_slice(&data_length_bytes);
    offset += mem::size_of::<u16>();
    
    // append data
    packet[offset..offset + data.len()].copy_from_slice(&data);
    hash_vec.extend_from_slice(&data);
    offset += data.len();
    
    // compute and append chunk hash
    let chunk_hash = compute_sha256_hash(&hash_vec);
    packet[offset..offset + chunk_hash.len()].copy_from_slice(&chunk_hash);
    
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
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let actual: [u8; 512] = packet::encode_packet(data);
        let expected: [u8; 512] = [0, 45, 1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 71, 32, 243, 31, 162, 211, 129, 246, 207, 35, 206, 186, 164, 176, 168, 165, 176, 142, 231, 133, 53, 190, 152, 159, 145, 197, 127, 235, 87, 208, 246, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decode_packet() {
        let expected = Packet {
            data_length: 45, 
            data: vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1],
            chunk_hash: [71, 32, 243, 31, 162, 211, 129, 246, 207, 35, 206, 186, 164, 176, 168, 165, 176, 142, 231, 133, 53, 190, 152, 159, 145, 197, 127, 235, 87, 208, 246, 62],
        };

        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let packet: [u8; 512] = packet::encode_packet(data);
        let actual = packet::decode_packet(packet);

        // need to wrap expected in Ok so that it matches the actual output, which hopefully is also Ok
        assert_eq!(actual, Ok(expected));
    }

    // I wasn't convinced that the PartialEq that rust autogenerated for Packet struct would be correct
    #[test]
    fn test_unequal_packets() {
        let expected = Packet {
            data_length: 87,
            data: vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1],
            chunk_hash: [225, 12, 171, 217, 101, 208, 53, 140, 202, 193, 162, 185, 202, 9, 198, 105, 184, 61, 132, 233, 44, 148, 213, 111, 38, 87, 245, 175, 76, 14, 186, 117],
        };

        let data = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let packet: [u8; 512] = packet::encode_packet(data);
        let actual = packet::decode_packet(packet);

        assert_ne!(actual, Ok(expected));
    }

    #[test]
    fn test_hash_check_failure() {
        let data = vec![1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1];
        let mut packet: [u8; 512] = packet::encode_packet(data);

        let chunk_hash_start = 2 + 2 + 8 + 11; // header + filename + data
        packet[chunk_hash_start] ^= 0xFF; // flip bits of chunk hash to cause error (using XOR)
        let actual = packet::decode_packet(packet);
        
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err(), "Computed chunk hash does not match chunk hash within packet.");
    }
}