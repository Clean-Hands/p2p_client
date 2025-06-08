# p2p_client

## Description
Our project is a [peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer) file sharing client.

A peer-to-peer file-sharing network is a [decentralized network](https://en.wikipedia.org/wiki/Decentralized_web) where each member of the network can send and receive files to any other member. An instance acting as a requester initiates a connection with a second instance acting as a listener. The listener will then send the requested file to the requester.

The project idea sprang from wanting to conveniently share large files with peers (ha!) on campus without the hassle of exchanging files physically or through other roundabout means. This use case motivated our tool's core architecture; you locally maintain a list of trusted peers (your friends) and files you want accessible to others. 

Below you will see us discuss a catalog feature and a list of known peers. The point of the catalog is to allow the listener specify exactly which files it is allowed to send and save relevant information about those files. The point of the list of known peers is to allow the user to not need to type in an entire IP address every time. By adding a peer into the list of known peers under an alias, you don't need to remember which IP belongs to someone, you just need to remember the alias you gave the IP.

The catalog and list of known peers is saved in a static directory whose location is dependent on OS:
- Linux: `/home/[user]/.local/share/p2p_client`
- macOS: `/Users/[user]/Library/Application Support/com.LLR.p2p_client`
- Windows: `C:\Users\[user]\AppData\Roaming\LLR\p2p_client\data`

## Getting Started
### Install dependencies
- Install rust and other necessary tools by following [this guide](https://doc.rust-lang.org/book/ch01-01-installation.html) to install rustup.
- Clone [our repository](https://github.com/rubenboero21/cs347)
  - `git clone https://github.com/rubenboero21/cs347.git`

### Build the Code
- Navigate to the `p2p_client` directory.
- Build the code for release (optimized):
  - `cargo build --release`
  - This creates an executable in `p2p_client/target/release` called `p2p_client`.
- You can now run the code by running the executable.

### Run the code
- Navigate to the directory that contains the executable (`p2p_client/target/release` by default).
  - If you want to launch the graphical user interface:
    - Run `./p2p_client` (Unix) or `.p2p_client` (Windows).
  - If you want to use the command line interface:
    - Run `./p2p_client -h ` (Unix) or `.p2p_client -h` (Windows) to view the options for the CLI.
    - More details on the CLI can be found in [running.md](https://github.com/rubenboero21/cs347/blob/main/doc/running.md).
- From within the `p2p_client` directory:
  - You can generate and open local documentation for our app by running `cargo doc --open`.
  - You can run our unit tests with `cargo test`. 
    - See [testing.md](https://github.com/rubenboero21/cs347/blob/main/doc/testing.md) for more details.

## Existing Features
- A graphical user interface can be started by running the `p2p_client` executable. See above [Getting Started](https://github.com/rubenboero21/cs347/blob/main/README.md#getting-started) section for how to build the executable.
- The code is broken into two halves: a **listener** and a **requester**. The listener listens for requests and fulfills them. The requester asks the listener for services. 
- **Listener features**:
  - The listener can handle multiple requests at once via [rust's asynchronous feature](https://rust-lang.github.io/async-book/).
  - Add a file to the listener's catalog of available files.
    - The catalog contains information (hash, file size, and file name) about all files that are available to request. Note, only files present in the listener's catalog are able to be sent to a requester.
  - Remove a file from the catalog.
  - View the catalog.

- **Requester features**:
  - Add an IP with an alias to your list of known peers.
    - The purpose of this command is to allow the user to associate IPs with a human-readable alias. Once added to the list of peers, the alias can be used in place of an IP.
  - Check if a specific peer is listening for requests.
  - Request the catalog of a specific peer.
  - Send a file request to a listening peer.
  - Remove an IP from your list of known peers.
  - View your list of known peers.

## Future Improvements / Known Issues
- We have a bare-bones graphical user interface working, but it could be made better in the following ways:
  - Built in instructions for how to use the app.
  - Sizing and spacing of elements could be more polished.
  - The catalog edit window relies on the GUI updating many times a second rather than permanently loading the needed information into the element. This will likely cause issues if the catalog is very large. Refer to lines 419-445 in [gui.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/gui.rs) to see the problematic code.
- Computing a file hash and sending a file is slow:
  - Unsure if there is a way to make computing a file hash faster (there probably is).
    - Computing a file hash occurs in `compute_hash()` function within [listener.rs](https://github.com/rubenboero21/cs347/blob/gui/p2p_client/src/listener.rs).
  - There is most likely ways to increase the speed of file sending.
    - File sending happens in the `fulfill_file_request()` function within [listener.rs](https://github.com/rubenboero21/cs347/blob/gui/p2p_client/src/listener.rs).
- Our unit tests perform a file transfer across two peer instances on the same device. To make our tests more robust implementing architecture capable of testing *between* device file transfer would be beneficial.
- Some of our unit tests rely simply on the fact that the called function does not return an error. (We think this is passable because we are careful in the way we check for and return errors) They could be improved by checking that the returned item is also of the correct form. For example, `test_catalog_request()` in [requester.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/requester.rs) does not check that the catalog is returned in the correct form. 
- If a Windows user pings themselves, an error occurs.