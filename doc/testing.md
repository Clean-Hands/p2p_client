# testing

## Automated Unit Testing
We are using the [Rust unit test functionality](https://doc.rust-lang.org/book/ch11-00-testing.html) managed by cargo. 

To run the tests, run `cargo test` within the [p2p_client](https://github.com/rubenboero21/cs347/tree/main/p2p_client) directory. If you do not have cargo installed, you can get it [here](https://www.rust-lang.org/tools/install).

Tests are present as modules at the bottom of [main.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/main.rs), [file_rw.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/file_rw.rs), and [packet.rs](https://github.com/rubenboero21/cs347/blob/main/p2p_client/src/packet.rs).


## Manual Testing
We have created a rudimentary Docker container system that allows us to simulate multiple peers on a single machine. Documentation can be found [here](https://github.com/rubenboero21/cs347/tree/main/docker).

A TL;DR to run the containers:
- From the root directory of cs347:
  - `docker build -f docker/Dockerfile -t p2p_client .`
  - `docker run -it --rm --network bridge p2p_client`

As many peers as needed can be set up in this way. The client app can then be run on each peer as if they were their own machine. See [the running document](https://github.com/rubenboero21/cs347/blob/main/doc/running.md) for more information.

A TL;DR to run the code in each container (2 peers):
- On peer 1 (Alice) acting as receiver:
  - cargo run <Bob's IP address> -p <path to save file>
- On peer 2 (Bob) acting as sender:
  - cargo run <Alice's IP address> -f <file to send>


## Un-implemented tests we should eventually implement
- Docker compose script that can automatically spin up peers, send files, and test that sending/receiving was successful. (Basically, run the above manual Docker tests automatically.)
