//! file_rw.rs
//! by Lazuli Kleinhans and Ruben Boero
//! April 29th, 2025
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


    #[test]
    fn test_open_iterable_file_and_read_correct_bytes() {
        let test_filename = "test_open_iterable_file.txt";
        let expected_data = b"Ruben said Lazuli was here :)".to_vec();

        write_file_bytes(test_filename, &expected_data);

        let mut actual_data = vec![];
        let bytes = open_iterable_file(&test_filename.to_string());

        for byte in bytes {
            match byte {
                Ok(b) => actual_data.push(b),
                Err(e) => panic!("Unable to read next byte: {e}"),
            }
        }

        assert_eq!(actual_data, expected_data);

        std::fs::remove_file(test_filename).expect("Failed to remove file");
    }


    #[test]
    fn test_open_writable_file_and_write_bytes() {
        use std::io::Write;

        let test_filename = "test_open_writable_file.txt";
        let to_write1 = b"partial write test ".to_vec();
        let to_write2 = b"partial write test part 2 electric boogaloo".to_vec();
        let mut expected_data = to_write1.clone();
        expected_data.extend(&to_write2);

        let mut file = open_writable_file(test_filename);
        file.write_all(&to_write1).expect("Failed to write to file");
        file.write_all(&to_write2).expect("Failed to write to file");

        let actual_data = read_file_bytes(&test_filename.to_string());

        assert_eq!(actual_data, expected_data);

        std::fs::remove_file(test_filename).expect("Failed to remove file");
    }


    // do we want the read_file_bytes function to return an empty array? or do we want it to return a Result
    // type that can contain an error or a filled vector? this would allow code to handle an error better 
    // since we could check for en Err return
    #[test]
    fn test_read_from_nonexistent_file() {
        let nonexistent_file = "i_dont_exist.txt";
        let data = read_file_bytes(&nonexistent_file.to_string());

        assert_eq!(data, Vec::<u8>::new());
    }


    // do we want write_file_bytes function to just print an error? or do we want it to return a Result type
    // that would allow us to handle the error within the code since we can check for an Err return
    // this test is useless rn, all it does is check that the path wasn't created. it has no way of telling
    // if the function encountered an error or not. Returning Result type would allow us to check this
    #[test]
    fn test_write_to_nonexistent_dir() {
        let nonexistent_path = "nonexistent_dir/neither_do_i.txt";
        let to_write = b"i will never be written to a file bc of the bad path".to_vec();

        write_file_bytes(nonexistent_path, &to_write);
        
        // check the file was not created
        assert!(!std::path::Path::new(nonexistent_path).exists());
    }
}