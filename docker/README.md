# How to use Docker to simulate multiple parties trying to connect

- Build and run the Docker image:
  - Need to be in the root directory of cs347
  - ```docker build -f docker/Dockerfile -t p2p_client .```
    - Docker needs the contents of the COPY to be within the directory that we build from, but it also needs access to the Dockerfile, so we call docker build from the root and pass in the location of the Dockerfile
  - ```docker run -it --rm --network bridge --name <container name> <image name>```
    - bridge is a built in Docker network to connect containers via IP address
  - for example:
    - ```docker build -t p2p_client .```
    - ```docker run -it --rm --network bridge p2p_client```

- Connect containers together:
  - note the container IP that is printed when the container opens
  - run the rust app:
    - ```cargo run p2p_client [username] [port] [IP address ...]```
    - for example:
      - ```cargo run p2p_client Alice 7878 172.17.0.2```

# TODO
- Every time code is changed, the containers need to be restarted. It is **very** tedious to start the rust app across multiple containers. A way to automate this or make it easier would be nice, but not needed.
- Possibly could write a script and import it into the container that fills in most of the cargo run command and has the user input port and IP address(es)