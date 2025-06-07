# p2p_client

## Description
Our project is a [peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer) file sharing client.

A peer-to-peer file-sharing network is a [decentralized network](https://en.wikipedia.org/wiki/Decentralized_web) where each member of the network can send and receive files to any other member. An instance acting as a requester initiates a connection with a second instance acting as a listener. The listener will then send the requested file to the requester.

## Getting Started for Developers
### Install dependencies
- Install rust and other necessary tools by following [this guide](https://doc.rust-lang.org/book/ch01-01-installation.html) to install rustup.
- Clone [our repository](https://github.com/rubenboero21/cs347)
  - `git clone https://github.com/rubenboero21/cs347.git`

# UPDATE BELOW TO MATCH GUI AND/OR EXECUTABLE
### Run the code
- Navigate to the `p2p_client` directory
- Run `cargo run` to build and run the app
  - By running with no arguments, the app will display the available commands.
  - Alternatively, refer to the quick start guide and available commands below.
- You can generate and open local documentation for our app by running `cargo doc --open`.
- You can run our unit tests with `cargo test`. See [testing.md](https://github.com/rubenboero21/cs347/blob/main/doc/testing.md) for more details.

<details>
<summary>Quick Start</summary>

### Sending Files
1. Choose a file that you want to make available for download
2. Add the file to your catalog with `cargo run listen add-file <file path>`
3. Start listening for incoming requests with `cargo run listen start`

### Downloading Files
1. Get the IP address of the peer you want to request a file from
2. Check they are online with `cargo run request ping <IP address>`
3. If they are online, figure out what files they have available for download with `cargo run request catalog <IP address>`
4. Choose one of the files they have available, and copy its hash
5. Request the file (and optionally choose where to save it) with `cargo run request file <IP address> <file hash> [save path]`

### Testing File Transfers Locally
- Open 2 terminal windows
- Use the first window as the sender. Follow the above instructions for sending files in this window
- Use the second window as the requester. Follow the above instructions for downloading files in this window.   
  - You can use `127.0.0.1` (localhost) as the IP address to request from, or you can specify the IP address of your machine on your network
  - **WARNING**: If you try to save the file in the same directory as you are uploading it from, the sender and requester will be reading and writing to the same file, which will likely corrupt the file's contents.
</details>

<details>
<summary>Available CLI Commands</summary>

### `listen` subcommand
  - Listen for incoming file requests:
    - `cargo run listen start`
  - Add a file to your local catalog of files available to download:
    - `cargo run listen add-file <path to file>`
  - Remove a file from your local catalog:
    - `cargo run listen remove-file <file hash>`
    - If the file hash is `DELETE-ALL`, all entries in the catalog will be deleted
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
    - If the peer alias is `DELETE-ALL`, all entries in the list of peers will be deleted
  - View your local list of known peers:
    - `cargo run request view-ips`
</details>


## Existing Features
- # UPDATE BELOW BULLET POINT
- A graphical user interface can be started by running `cargo run`. 
  - The same functionalities listed below exists for the user running the gui.
- **As a listener:** 
  - Start a listener that sends requested files to peers. The listener can handle multiple requests at once via [rust's asynchronous feature](https://rust-lang.github.io/async-book/).
    - `cargo run listen start`
  - Add a file to the listener's catalog of available files. The catalog contains information (hash, file size, and file name) about all files that are available to request. Note, only files present in the listener's catalog are able to be sent to a requester.
    - `cargo run listen add-file <file path>`
  - Remove a file from the catalog.
    - `cargo run listen remove-file <file hash>`
    - If the specified file hash is `DELETE-ALL`, then all entries in the catalog will be removed.
  - View the catalog.
    - `cargo run listen view-catalog`
- **As a requester:**
  - Check if a specific peer is listening for requests.
    - `cargo run request ping <peer IP address or alias>`
  - Request the catalog of a specific peer. This allows the requester to get the hash of a file they want to request. See the Quick Start section above for a typical flow of commands to run in order to request a file.
    - `cargo run request catalog <peer IP address or alias>`
  - Send a file request to a listening peer.
    - `cargo run request file <peer IP address or alias> <file hash> [OPTIONAL: save location]`
    - An `alias` is associated with an IP address by running the `add-ip` command. See the add-ip bullet below for more details.
    - The default save location is the current working directory (the folder in which you run the `cargo run ...` command).
  - Add an IP to your list of known peers.
    - The purpose of this command is to allow the user to associate IPs with a human-readable alias. Once added to the list of peers, the alias can be used in place of an IP. For example, you could add 'localhost' as an alias for '127.0.0.1' by running: `cargo run request add-ip localhost 127.0.0.1`. This would allow you to type `localhost` in place of the IP address wherever an IP address is required.
    - `cargo run request add-ip <alias> <peer IP address>`
  - Remove an IP from your list of known peers.
    - `cargo run request remove-ip <peer alias>`
    - If the specified peer alias is `DELETE-ALL`, then all entries in the list will be removed.
  - View your list of known peers.
    - `cargo run request view-ips`


## TODO
# UPDATE LATER
- We have a rudimentary graphical user interface working, but it could be made better in the following ways:
 - UPDATE

- Our unit tests are not able to test the functionality of our code across devices. To make our tests more robust, implementing a system to automatically test across device testing would be beneficial.
- If a Windows user pings themselves, an error occurs.
