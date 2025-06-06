# testing

## Automated Unit Testing
We are using the [Rust unit test functionality](https://doc.rust-lang.org/book/ch11-00-testing.html) managed by cargo. 

**To run the tests**, run `cargo test` within the [p2p_client](https://github.com/rubenboero21/cs347/tree/main/p2p_client) directory. If you do not have cargo installed, you can get it [here](https://www.rust-lang.org/tools/install). Before running the tests, all local listener processes should be terminated. Some of these tests begin their own listener processes, so if a listener process is already running, conflicts occur.

Tests are present as modules at the bottom of the following files: 
- [main.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/main.rs)
- [file_rw.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/file_rw.rs)
- [packet.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/packet.rs)
- [encryption.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/encryption.rs)
- [listener.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/listener.rs)
- [requester.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/requester.rs).


## Manual Testing
Our code is split into two independent halves: requester and listener. As such, the code can be manually tested by creating a requester and listener process on the same local machine. 

To setup manual testing on a single machine:
- Open 2 terminal windows
- Use the first window as the sender. Follow the above instructions for sending files in this window
- Use the second window as the requester. Follow the above instructions for downloading files in this window.   
  - You can use `127.0.0.1` (localhost) as the IP address to request from, or you can specify the IP address of your machine on your network
  - **WARNING**: If you try to save the file in the same directory as you are uploading it from, the sender and requester will be reading and writing to the same file, which will corrupt the file's contents.