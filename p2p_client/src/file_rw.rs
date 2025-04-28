//! file_rw.rs
//! by Lazuli Kleinhans
//! April 28th, 2025
//! CS347 Advanced Software Design

use std::fs::{self, File};
use std::io::{self, Read};
use std::process;


/// Return a `Vec<u8>` filled with ALL of the bytes of the passed filename
/// 
/// If fails to read in file, returns an empty `Vec<u8>`
/// 
/// If you don't want to read in all of the bytes at once, consider using `open_iterable_file()`
pub fn read_file_bytes(file_path: &String) -> Vec<u8> {
    match fs::read(file_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("Unable to read in file.");
            vec![]
        }
    }
}


/// Returns an iterable `Bytes<File>` object that can get a file's bytes one by one
/// 
/// Useful if you don't want to read in all bytes at once or be able to
/// pause and continue reading bytes without losing your place in the file
/// 
/// # Example
/// 
/// ```rust
/// let bytes = file_rw::open_iterable_file(&String::from("test.txt"));
/// for byte in bytes {
///     match byte {
///         Ok(b) => println!("{b}"),
///         Err(e) => eprintln!("Unable to read next byte: {e}")
///     }
/// }
/// ```
pub fn open_iterable_file(file_path: &String) -> io::Bytes<File>{
    let f = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Couldn't open file: {e}");
            // TODO: decide on a better way to handle failure to read
            process::exit(1);
        }
    };
    return f.bytes();
}


/// Writes all passed bytes to the passed file, and closes the file.
/// 
/// If you want to write bytes in multiple bursts, consider using `open_writable_file()`
pub fn write_file_bytes(file_path: &str, bytes: &Vec<u8>) {
    if let Err(e) = fs::write(file_path, bytes) {
        eprintln!("Failed to write bytes to file: {e}");
    };
}


/// Returns a `File` object that bytes can be written to in multiple bursts
/// 
/// Useful if you don't want to write all bytes at once or be able to
/// pause and continue writing bytes without losing your place in the file
/// 
/// # Example
/// 
/// ```rust
/// let mut file = open_writable_file("test.txt");
/// for byte in bytes {
///     if let Err(e) = file.write(&[byte]) {
///         eprintln!("Failed to write byte to file: {e}");
///     }
/// }
/// ```
pub fn open_writable_file(file_path: &str) -> File {
    match File::create(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Couldn't open file: {e}");
            // TODO: decide on a better way to handle failure to open file
            process::exit(1);
        }
    }
}


#[cfg(test)]
mod tests { 
    use super::*;
    #[test]
    fn test_read_write_file_bytes() {
        let test_filename = "test_read_write_file.txt";

        let expected_data = vec![104, 101, 108, 108, 111]; // "hello"
        write_file_bytes(test_filename, &expected_data);

        let actual_data = read_file_bytes(&test_filename.to_string());

        assert_eq!(actual_data, expected_data);
 
        // cleanup
        std::fs::remove_file(test_filename).expect("Failed to remove file");
    }
}