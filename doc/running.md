# running

- Navigate to the ```p2p_client``` directory
- Use [cargo](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html#building-and-running-a-cargo-project) to build and run the rust program:
- Sender:
  - `cargo run send`
- Requester:
  - `cargo run request <IP to request from> <file name> <optional: path to save file>`
  - If no path to save file is specified, will save to current directory
  - Currently, file name is being used, in the future, file hash will be used