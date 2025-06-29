//! encryption.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! June 4th, 2025
//! CS347 Advanced Software Design

use crate::packet;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use std::io::Write;
use std::net::TcpStream;

// Aes256Gcm appends a 16 byte verification tag to the end of the ciphertext
pub const AES256GCM_VER_TAG_SIZE: usize = 16;



fn increment_nonce(nonce: &mut [u8; 12]) {
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



/// Encrypt message given nonce, cipher, and message
pub fn encrypt_message(
    nonce: &mut [u8; 12],
    cipher: &Aes256Gcm,
    message: &[u8; packet::PACKET_SIZE],
) -> Result<Vec<u8>, String> {
    let enc_nonce = Nonce::from_slice(nonce);
    let ciphertext = match cipher.encrypt(&enc_nonce, message.as_ref()) {
        Ok(c) => c,
        Err(e) => return Err(format!("Encryption failed: {}", e)),
    };

    increment_nonce(nonce);
    Ok(ciphertext)
}



/// Decrypt message given nonce, cipher, and ciphertext
pub fn decrypt_message(
    nonce: &mut [u8; 12],
    cipher: &Aes256Gcm,
    ciphertext: &[u8; packet::PACKET_SIZE + AES256GCM_VER_TAG_SIZE],
) -> Result<[u8; packet::PACKET_SIZE], String> {
    let denc_nonce = Nonce::from_slice(nonce);
    let plaintext_as_array = match cipher.decrypt(&denc_nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            // convert output of decrypt from vec to array so it plays nicely with decode function
            let mut plaintext_as_array = [0; packet::PACKET_SIZE];
            for i in 0..packet::PACKET_SIZE {
                plaintext_as_array[i] = plaintext[i];
            }
            plaintext_as_array
        }
        Err(e) => return Err(format!("Decryption failed {}", e)),
    };
    increment_nonce(nonce);
    Ok(plaintext_as_array)
}



/// Writes the String `message` to `TcpStream` object `stream`.
pub fn send_to_connection(
    stream: &mut TcpStream,
    nonce: &mut [u8; 12],
    cipher: &Aes256Gcm,
    message: [u8; packet::PACKET_SIZE],
) -> Result<(), String> {
    // encrypt message
    let ciphertext = match encrypt_message(nonce, cipher, &message) {
        Ok(c) => c,
        Err(e) => return Err(format!("Encryption failed: {e}")),
    };

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
