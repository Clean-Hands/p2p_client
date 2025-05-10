# running

- Navigate to the `p2p_client` directory
- Use [cargo](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html#building-and-running-a-cargo-project) to build rust program:
  - `cargo build`
- Run the compiled program:
  - On Mac/Linux: `./target/debug/p2p_client`
  - *or*
  - On Windows: `.\target\debug\p2p_client.exe`
- To get instructions on how to use the client:
  - `./target/debug/p2p_client --help`
  - *or*
  - `.\target\debug\p2p_client.exe --help`
- You can also directly run the program using `cargo run` [parameters]` if you already know the options.
- To find your IP address on Unix:
  - run `ifconfig | grep inet` and look for the line that is not localhost (127.0.0.1)