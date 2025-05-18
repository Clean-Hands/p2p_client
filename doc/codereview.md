# codereview

## Project Description
Our project is a [peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer) file sharing client.

A peer-to-peer file-sharing network is a decentralized network where each member of the network has the capability to send and receive files (each member can be both a client or server). One instance acting as a requester initiates a connection with a second instance acting as a listener. The listener will then send the requested file to the requester. 

Many peer-to-peer networks have a centralized server to provide a way to discover other peers to connect to. We do not have this functionality yet, but we may add it if we have time. 

## Project Status
Right now, you can:
- add a file to your local list of available files
- start listening for incoming file requests (and serve requested files)
- request a file from a peer
- download the file to a chosen directory
- add IPs to a list of known peers, optionally adding an alias so you know which IP belongs to which user
- ping a specific peer to see if they are available for file requests
- request a peer's file catalog to see what files they have available to download  

## How to Run
Refer to the [running.md](https://github.com/rubenboero21/cs347/blob/main/doc/running.md) document.

## Questions We Would Like Answered
- Does the code organization/architecture make sense?
- Does the documentation (both in the code and in the docs folder) make sense? 
  - If it doesn't make sense, where/what doesn't make sense?
  - If you have cargo installed, you can run `cargo doc --open` to create html and css for a website containing documentation for the entire project. Does this doc look helpful? Are the function descriptions useful? Is there anything you wish we included that we didn't?
    - If you don't have cargo installed, it can be installed [here](https://www.rust-lang.org/tools/install) along with rust.
- What is the experience like of sending files? Are there too many manual steps?
  - e.g. manually finding an IP to connect to, then requesting their catalog, then copying in the hash of the file that you want to request, then finally sending a request for a file