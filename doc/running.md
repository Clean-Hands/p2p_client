# running

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

### `listen` subcommand
  - Listen for incoming file requests:
    - `cargo run listen start`
  - Add a file to your local catalog of files available to download:
    - `cargo run listen add-file <path to file>`
  - Remove a file from your local catalog:
    - `cargo run listen remove-file <file hash>`
  - View your local catalog:
    - `cargo run listen view-catalog`
### `request` subcommand
  - Send a file request to a listening peer:
    - `cargo run request file <peer IP address> <file hash> [OPTIONAL: save location]`
  - Request the catalog of a specific peer:
    - `cargo run request catalog <peer IP address>`
  - Check if a specific peer is up and listening for requests:
    - `cargo run request ping <peer IP address>`
  - Add an IP to your list of known peers:
    - `cargo run request add-ip <peer IP address> [OPTIONAL: alias]`
  - Remove an IP from your list of known peers:
    - `cargo run request remove-ip <peer IP address>`
  - View your local list of known peers:
    - `cargo run request view-ips`