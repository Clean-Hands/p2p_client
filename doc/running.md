# running
This document is intended to describe how to use the command line interface in detail.

Ensure you have navigated to the `p2p_client` directory before attempting to run any of the following commands.

(These commands use [cargo](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html#building-and-running-a-cargo-project) to build and run the rust program.)

## Quick Start

### Sending Files
1. Choose a file that you want to make available to download
2. Add the file to your catalog with `cargo run listen add-file <file path>`
3. Start listening for incoming requests with `cargo run listen start`

### Downloading Files
1. Get the IP address of the peer you want to request a file from
2. Check they are online with `cargo run request ping <IP address>`
3. If they are online, figure out what files they have available for download with `cargo run request catalog <IP address>`
4. Choose one of the files they have available, and copy its hash
5. Request the file (and optionally choose where to save it) with `cargo run request file <IP address> <file hash> [save path]`

## Available Commands
This document assumes you are using cargo to build the project. If you would prefer to use the executable, replace `cargo run` with `p2p_client` (`p2p_client.exe` on Windows) in the following commands.
### CLI specific commands:
- Help command (display information about the app and its commands).
- This command is the only one that does not work when running the app with cargo. You must run the executable file directly. If you do not run the executable, the cargo's help information will print.
- For example, assuming you are in the `p2p_client` directory and on a Unix system:
  - Build the executable: `cargo build` 
  - Run the executable and specify the help option: `./target/debug/p2p_client -h`
### `listen` subcommand
  - Listen for incoming file requests from peers. The listener can handle multiple requests at once via [rust's asynchronous feature](https://rust-lang.github.io/async-book/):
    - `cargo run listen start`
  - Add a file to your local catalog of files available to download:
    - `cargo run listen add-file <path to file>`
    - The catalog contains information (hash, file size, and file name) about all files that are available to request. Note, only files present in the listener's catalog are able to be sent to a requester.
  - Remove a file from your local catalog:
    - `cargo run listen remove-file <file hash>`
    - If the file hash is `DELETE-ALL`, all entries in the catalog will be deleted
  - View your local catalog:
    - `cargo run listen view-catalog`
### `request` subcommand
  - Check if a specific peer is up and listening for requests:
    - `cargo run request ping <peer IP address or alias>`
    - An `alias` is associated with an IP address by running the `add-ip` command
  - Send a file request to a listening peer:
    - `cargo run request file <peer IP address or alias> <file hash> [OPTIONAL: save location]`
    - An `alias` is associated with an IP address by running the `add-ip` command
    - The default save location is the current working directory (the folder in which you run the `cargo run ...` command).
  - Request the catalog of a specific peer:
    - `cargo run request catalog <peer IP address or alias>`
    - An `alias` is associated with an IP address by running the `add-ip` command
    - This command allows the requester to get the hash of a file they want to request. See the Quick Start section above for a typical flow of commands to run in order to request a file.
  - Add an IP to your list of known peers:
    - `cargo run request add-ip <alias> <peer IP address>`
    - The purpose of this command is to allow the user to associate IPs with a human-readable alias. Once added to the list of peers, the alias can be used in place of an IP. For example, you could add 'localhost' as an alias for '127.0.0.1' by running: `cargo run request add-ip localhost 127.0.0.1`. This would allow you to type `localhost` in place of the IP address wherever an IP address is required.
  - Remove an IP from your list of known peers:
    - `cargo run request remove-ip <peer alias>`
    - If the peer alias is `DELETE-ALL`, all entries in the list of peers will be deleted
  - View your local list of known peers:
    - `cargo run request view-ips`