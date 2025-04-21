use sha256::{digest, try_digest};

struct Packet {
    packet_length: u32,
    filename_len: u32,
    filename: &str,
    data: Vec<u8>,
    chunk_hash: [u8; 32],
    file_hash: [u8; 32],
}

impl Packet {
    /// wrap data
    fn encode_packet(data: Vec<u8>) -> Packet {
        // 
    }

    /// extract data from packet and verify integrity
    fn decode_packet(packet: Packet) -> Vec<u8> {

    }
}