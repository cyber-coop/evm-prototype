##### BUILDER #####
FROM rust:latest as builder

WORKDIR /usr/src/evm-prototype
COPY . .
RUN cargo install --path .

##### RUNNER #####
FROM debian:bookworm

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol> and Mehdi NEDJAR"
LABEL description="Custom REVM allowing to connect to database made by our homemade indexer."

COPY --from=builder /usr/local/cargo/bin/evm-prototype /usr/local/bin/evm-prototype

RUN apt-get update && rm -rf /var/lib/apt/lists/*

# default env
# TODO: support different networks
# ENV NETWORK "ethereum_rinkeby"

CMD evm-prototype