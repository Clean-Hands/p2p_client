# testing

## Automated Unit Testing
We plan to use the [Rust unit test functionality](https://doc.rust-lang.org/rust-by-example/testing/unit_testing.html) managed by cargo.

## Manual Testing
We have created a rudimentary Docker container system that allows us to similate multiple peers on a single machine. Documentation can be found [here](https://github.com/rubenboero21/cs347/tree/main/docker).

A TL;DR to run the containers:
- From the root directory of cs347:
  - ```docker build -f docker/Dockerfile -t p2p_client .```
  - ```docker run -it --rm --network bridge p2p_client```

As many peers as needed can be set up in this way. 

We also are writing basic tests in main functions as we code to verify that the code appears to be working as intended.
