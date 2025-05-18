# running

Ensure you have navigated to the `p2p_client` directory before attempting to run any of the following commands.

(These commands use [cargo](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html#building-and-running-a-cargo-project) to build and run the rust program.)
## `listen` subcommand
  - Listen for incoming file requests:
    - `cargo run listen start`
  - Add a file to your local catalog of files available to download:
    - `cargo run listen add-file <path to file>`
  - Remove a file from your local catalog:
    - `cargo run listen remove-file <file hash>`
  - View your local catalog:
    - `cargo run listen view-catalog`
## `request` subcommand
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