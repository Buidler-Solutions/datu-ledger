# Builds datu and datu-indexer from this repository, then ships a slim runtime.
# Context: repository root (docker build -f deploy/projection/Dockerfile .)
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p datu-cli \
 && cargo build --release -p datu-indexer --features postgres

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A dedicated unprivileged account: neither the node nor the indexer needs
# root, and the data directory is the only writable path in the image.
RUN groupadd -g 10001 datu \
 && useradd -u 10001 -g datu -M -s /usr/sbin/nologin datu \
 && mkdir -p /data && chown datu:datu /data

COPY --from=build /src/target/release/datu /usr/local/bin/datu
COPY --from=build /src/target/release/datu-indexer /usr/local/bin/datu-indexer

USER datu
WORKDIR /data

# Liveness: the store answers its own status for both services in the
# projection stack (they share the node volume at /data/node).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["datu", "--data-dir", "/data/node", "status"]
