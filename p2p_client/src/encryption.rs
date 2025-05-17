//! encryption.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! May 17th, 2025
//! CS347 Advanced Software Design

use crate::packet;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use sha2::digest::generic_array::{GenericArray, typenum::U12};
use std::io::Write;
use std::net::TcpStream;



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
pub fn encrypt_message(
    nonce: &GenericArray<u8, U12>,
    cipher: &Aes256Gcm,
    message: &[u8; packet::PACKET_SIZE],
) -> Result<Vec<u8>, String> {
    match cipher.encrypt(&nonce, message.as_ref()) {
        Ok(c) => return Ok(c),
        Err(e) => return Err(format!("Encryption failed: {}", e))
    };
}



/// decrypt message given nonce, cipher, and ciphertext
///
/// ciphertext is assumed to be 528 bytes because packet is always 512 bytes long & Aes256Gcm adds a 16
/// byte verification tag
pub fn decrypt_message(
    nonce: &GenericArray<u8, U12>,
    cipher: &Aes256Gcm,
    ciphertext: &[u8; packet::PACKET_SIZE + 16],
) -> Result<[u8; packet::PACKET_SIZE], String> {
    match cipher.decrypt(&nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            // convert output of decrypt from vec to array so it plays nicely with decode function
            let mut plaintext_as_array = [0; packet::PACKET_SIZE];
            for i in 0..packet::PACKET_SIZE {
                plaintext_as_array[i] = plaintext[i];
            }
            Ok(plaintext_as_array)
        },
        Err(e) => Err(format!("Decryption failed {}", e))
    }
}



/// Writes the String `message` to `TcpStream` object `stream`.
pub fn send_to_connection(
    stream: &mut TcpStream,
    nonce: &mut [u8; 12],
    cipher: &Aes256Gcm,
    message: [u8; packet::PACKET_SIZE],
) -> Result<(), String> {
    // encrypt message
    let enc_nonce = Nonce::from_slice(nonce);
    // this function call assumes that cipher is Some type, still need to check that cipher
    // is initialized correctly in start_sender_task
    let ciphertext = match encrypt_message(&enc_nonce, cipher, &message) {
        Ok(c) => c,
        Err(e) => return Err(format!("Encryption failed: {e}"))
    };

    // increment nonce outside scope of function
    increment_nonce(nonce);

    if let Err(e) = stream.write_all(&ciphertext) {
        return Err(format!("Failed to write to stream: {e}"));
    }

    Ok(())
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
