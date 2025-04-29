# How to use Docker to simulate multiple parties trying to connect

- Build and run the Docker image:
  - Need to be in the root directory of cs347 because of how I specified the path of entrypoint.sh and p2p_client
  - ```docker build -f <path to Dockerfile> -t <container name> <build context>```
    - Docker needs the contents of the COPY to be within the directory that we build from, but it also needs access to the Dockerfile, so we call docker build from the root and pass in the location of the Dockerfile (in the Dockerfile we specify the path to entrypoint.sh and p2p_client assuming we are in the root)
  - ```docker run -it --rm --network bridge --name <container name> <image name>```
    - bridge is a built in Docker network to connect containers via IP address
  - for example (from the root of cs347):
    - ```docker build -f docker/Dockerfile -t p2p_client .```
    - ```docker run -it --rm --network bridge p2p_client```

- Connect containers together:
  - note the container IP that is printed when the container opens
    - if you miss it, can run ```hostname -i``` to get it again
  - run the rust app:
    - ```cargo run [username] [port] [IP address ...]```
    - for example:
      - ```cargo run Alice 7878 172.17.0.2```

# TODO
- Every time code is changed, the containers need to be restarted. It is **very** tedious to start the rust app across multiple containers. A way to automate this or make it easier would be nice, but not needed.
  - Possibly could write a script and import it into the container that fills in most of the cargo run command and has the user input port and IP address(es)
- Needing to be in the root directory to build the container seems weird/bad. This is necessary because I hard code the path to entrypoint.sh and p2p_client in the Dockerfile assuming we're in the root.
  - It's possible to get rid of entrypoint.sh and just run the commands directly, but I thought the file was cleaner ... I'm not so sure now.
  - Could also git clone the code into the container, but that seems like unnecessary overhead every time we want to open a container. 
