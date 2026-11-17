# Builds datu and datu-indexer from this repository, then ships a slim runtime.
# Context: repository root (docker build -f deploy/projection/Dockerfile .)
FROM rust:1.84-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p datu-cli \
 && cargo build --release -p datu-indexer --features postgres

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/datu /usr/local/bin/datu
COPY --from=build /src/target/release/datu-indexer /usr/local/bin/datu-indexer
WORKDIR /data
