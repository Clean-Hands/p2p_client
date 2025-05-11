use std::net::{TcpStream, TcpListener};
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use crate::packet;

pub struct ConnectionInfo {
    pub sender_stream: TcpStream,
    pub dh_public_key: PublicKey,
    pub dh_private_key: Option<EphemeralSecret>,
    pub dh_shared_secret: Option<SharedSecret>,
    pub cipher: Option<Aes256Gcm>,
    pub nonce: [u8; 12]
}

// TODO, this seems janky and unintended within aes_gcm crate, look for better way to incr nonce
/// increment the nonce within the struct
pub fn increment_nonce(nonce: &mut [u8; 12]) {
    let mut carry = true;

    for byte in nonce.iter_mut().rev() {
        if carry {
            let (new_byte, overflow) = byte.overflowing_add(1);
            // dereference nonce's byte and update its actual value
            *byte = new_byte;
            carry = overflow;
        } else {
            break;
        }
    }
}

/// encrypt message given nonce, cipher, and message
pub fn encrypt_message(nonce: &GenericArray<u8, U12>, cipher: &Aes256Gcm, message: &[u8; packet::PACKET_SIZE]) -> Result<Vec<u8>, String> {
    match cipher.encrypt(&nonce, message.as_ref()) {
        Ok(c) => return Ok(c),
        Err(e) => {
            return Err(format!("Encryption failed: {}", e));

        }
    }; 
}

/// decrypt message given nonce, cipher, and ciphertext
/// 
/// ciphertext is assumed to be 528 bytes because packet is always 512 bytes long & Aes256Gcm adds a 16 
/// byte verification tag
pub fn decrypt_message(nonce: &GenericArray<u8, U12>, cipher: &Aes256Gcm, ciphertext: &[u8; packet::PACKET_SIZE + 16]) -> Result<[u8; 512], String> {
    match cipher.decrypt(&nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            // convert output of decrypt from vec to array so it plays nicely with decode function
            let mut plaintext_as_array = [0; packet::PACKET_SIZE];
            for i in 0..packet::PACKET_SIZE {
                plaintext_as_array[i] = plaintext[i];
            }
            return Ok(plaintext_as_array)
        },
        Err(e) => {
            return Err(format!("Decryption failed {}", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_increment_nonce() {
        let mut nonce = [0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);

        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);

        let mut nonce = [255u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0u8; 12]);
    }
}
