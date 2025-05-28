# p2p_client

## Description
Our project is a [peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer) file sharing client.

A peer-to-peer file-sharing network is a decentralized network where each member of the network has the capability to send and receive files (each member can be both a client or server). One instance acting as a requester initiates a connection with a second instance acting as a listener. The listener will then send the requested file to the requester. 

Many peer-to-peer networks have a centralized server to provide a way to discover other peers to connect to. We do not have this functionality yet, but we may add it if we have time. 


## Getting Started for Developers
### Install dependencies
- Install rust and other necessary tools by following [this guide](https://doc.rust-lang.org/book/ch01-01-installation.html) to install rustup.
- Clone [our repository](https://github.com/rubenboero21/cs347)

### Run the code
- Navigate to the `p2p_client` directory
- Run `cargo run` to build and run the app
  - By running with no arguments the app will display the commands available to run
- Alternatively, refer to the quick start guide and available commands below:

<details>
<summary>Quick Start</summary>

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
</details>

<details>
<summary>Available Commands</summary>

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
    - `cargo run request file <peer IP address or alias> <file hash> [OPTIONAL: save location]`
    - An `alias` is associated with an IP address by running the `add-ip` command
  - Request the catalog of a specific peer:
    - `cargo run request catalog <peer IP address or alias>`
    - An `alias` is associated with an IP address by running the `add-ip` command
  - Check if a specific peer is up and listening for requests:
    - `cargo run request ping <peer IP address or alias>`
    - An `alias` is associated with an IP address by running the `add-ip` command
  - Add an IP to your list of known peers:
    - `cargo run request add-ip <alias> <peer IP address>`
  - Remove an IP from your list of known peers:
    - `cargo run request remove-ip <peer alias>`
  - View your local list of known peers:
    - `cargo run request view-ips`
</details>


## Existing Features
- As a listener: 
  - Start a listener that sends requested files to peers. The listener can handle multiple requests at once.   
    - `cargo run listen start`
  - Add files to a catalog. The catalog contains information (hash, file size, and file location) about all files that are available to request.
    - `cargo run listen add-file <file path>`
  - Remove a file from the catalog.
    - `cargo run listen remove-file <file hash>`
    - If the specified file hash is `DELETE-ALL` then all entries in the catalog will be removed.
  - View the catalog.
    - `cargo run listen view-catalog`
- As a requester:
  - Send a file request to a listening peer.
    - `cargo run request file <peer IP address or alias> <file hash> [OPTIONAL: save location]`
    - An `alias` is associated with an IP address by running the `add-ip` command. See the add ip bullet below.
    - The default save location is the directory from which the code is run.
  - Request the catalog of a specific peer. This allows the requester to find the hash of the files they want to request.
    - `cargo run request catalog <peer IP address or alias>`
  - Check if a specific peer is listening for requests.
    - `cargo run request ping <peer IP address or alias>`
  - Add an IP to your list of known peers. The purpose of this command is to allow the user to associate IPs with a more human readable alias. Once added to the list of peers, the alias can be used in place of an IP. For example, you could add 'localhost' as an alias for '127.0.0.1', allowing you to type localhost in place of the IP address in all places where an IP address is required.
    - `cargo run request add-ip <alias> <peer IP address>`
  - Remove an IP from your lsit of known peers.
    - `cargo run request remove-ip <peer alias>`
  - View your list of known peers.
    - `cargo run request view-ips`

## TODO
We acknowledge that the current state of the program is cumbersome to use, requiring many commands to be run to request a single file as well as the use of many copies and pastes. To address this, we are working on creating a graphical user interface with the same features as the above command line interface. 