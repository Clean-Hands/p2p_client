# https://hub.docker.com/_/rust
FROM rust:latest

WORKDIR /usr/src/p2p_client
# import rust code into container
COPY p2p_client/ .

RUN cargo install --path .

# copy in bash script to run on entry that prints container's IP
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
# this will automatically run the app when container is launched
# CMD ["p2p_client"]
