//! file_rw.rs
//! by Lazuli Kleinhans, Ruben Boero
//! May 28th, 2025
//! CS347 Advanced Software Design

use std::fs::{self, File};
use std::path::PathBuf;



/// Return a `Vec<u8>` filled with ALL of the bytes of the passed file name
///
/// If you don't want to read in all of the bytes at once, consider using `open_iterable_file()`
///
/// # Example
///
/// ```rust
/// let bytes = match read_file_bytes(&String::from("test.txt")) {
///     Ok(b) => b,
///     Err(e) => eprintln!("{e}")
/// };
/// ```
pub fn read_file_bytes(file_path: &PathBuf) -> Result<Vec<u8>, String> {
    match fs::read(file_path) {
        Ok(d) => Ok(d),
        Err(e) => Err(format!("Unable to read in file: {e}"))
    }
}



/// Writes all passed bytes to the passed file, and closes the file
///
/// If you want to write bytes in multiple bursts, consider using `open_writable_file()`
///
/// # Example
///
/// ```rust
/// if let Err(e) = write_file_bytes(&String::from("test.txt"), vec![104, 101, 108, 108, 111]) {
///     eprintln!("{e}")
/// }
/// ```
#[allow(dead_code)]
pub fn write_file_bytes(file_path: &PathBuf, bytes: &Vec<u8>) -> Result<(), String> {
    match fs::write(file_path, bytes) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to write bytes to file: {e}"))
    }
}



/// Returns a `File` object that bytes can be written to in multiple bursts
///
/// Useful if you don't want to write all bytes at once or be able to
/// pause and continue writing bytes without losing your place in the file
///
/// # Example
///
/// ```rust
/// let mut file = match open_writable_file(&String::from("test.txt")) {
///     Ok(f) => f,
///     Err(e) => {
///         eprintln!("Failed to open file: {e}");
///         return;
///     }
/// };
///
/// for byte in bytes {
///     if let Err(e) = file.write(&[byte]) {
///         eprintln!("Failed to write byte to file: {e}");
///     }
/// }
/// ```
pub fn open_writable_file(file_path: &PathBuf) -> Result<File, String> {
    match File::create(file_path) {
        Ok(f) => Ok(f),
        Err(e) => return Err(format!("Couldn't open file: {e}"))
    }
}



/// Returns the size of a given file in bytes by reading the file's metadata
/// 
/// *does not read entire file into memory*
/// 
pub fn get_file_size(file_path: &PathBuf) -> Result<u64, String> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open file in get_file_size(): {e}"))
    };

    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Err(format!("Failed to get metadata for: {e}"))
    };

    Ok(metadata.len())
}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_read_write_file_bytes() {
        let test_file_name = PathBuf::from("test_read_write_file.txt");

        let expected_data = vec![104, 101, 108, 108, 111]; // "hello"
        if let Err(e) = write_file_bytes(&test_file_name, &expected_data) {
            panic!("{e}")
        }

        let actual_data = read_file_bytes(&test_file_name);

        assert_eq!(actual_data, Ok(expected_data));

        // cleanup
        fs::remove_file(test_file_name).expect("Failed to remove file");
    }

    #[test]
    fn test_open_writable_file_and_write_bytes() {
        use std::io::Write;

        let test_file_name = PathBuf::from("test_open_writable_file.txt");
        let to_write1 = b"partial write test ".to_vec();
        let to_write2 = b"partial write test part 2 electric boogaloo".to_vec();
        let mut expected_data = to_write1.clone();
        expected_data.extend(&to_write2);

        let mut file = match open_writable_file(&test_file_name) {
            Ok(f) => f,
            Err(e) => panic!("{e}")
        };
        file.write_all(&to_write1).expect("Failed to write to file");
        file.write_all(&to_write2).expect("Failed to write to file");

        let actual_data = match read_file_bytes(&test_file_name) {
            Ok(b) => b,
            Err(e) => panic!("{e}")
        };

        assert_eq!(actual_data, expected_data);

        fs::remove_file(test_file_name).expect("Failed to remove file");
    }

    #[test]
    fn test_read_from_nonexistent_file() {
        let nonexistent_file = PathBuf::from("i_dont_exist.txt");
        if let Ok(d) = read_file_bytes(&nonexistent_file) {
            panic!("Was able to read data from nonexistent file: {:?}", d);
        };
    }

    #[test]
    fn test_write_to_nonexistent_dir() {
        use std::path::Path;

        let nonexistent_path = PathBuf::from("nonexistent_dir/neither_do_i.txt");
        let to_write = b"i will never be written to a file bc of the bad path".to_vec();

        if let Ok(()) = write_file_bytes(&nonexistent_path, &to_write) {
            panic!("Was able to write data to nonexistent file.");
        };

        // check the file was not created
        assert!(!Path::new(&nonexistent_path).exists());
    }
}