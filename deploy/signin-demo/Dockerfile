# Two targets from one build, so the workspace compiles once:
#   target validator - the datu node (serve --read-only)
#   target dapp      - the relying-party server + the datu verifier binary
# Build context is the repository root. Every runtime stage is unprivileged.
FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release -p datu-cli \
 && mkdir -p /out \
 && cp target/release/datu /out/datu

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS validator
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 datu \
 && useradd -u 10001 -g datu -M -s /usr/sbin/nologin datu \
 && mkdir -p /data && chown datu:datu /data
COPY --from=build /out/datu /usr/local/bin/datu
USER datu
WORKDIR /data
EXPOSE 7474
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["datu", "--data-dir", "/data", "status"]

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS dapp-deps
WORKDIR /app
COPY web/signin-demo/package.json web/signin-demo/package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS dapp
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=dapp-deps /app/node_modules ./node_modules
COPY web/signin-demo/package.json web/signin-demo/server.mjs ./
# The verifier binary the server shells out to (datu signet auth-verify).
COPY --from=build /out/datu /usr/local/bin/datu
ENV NODE_ENV=production PORT=5176 HOST=0.0.0.0 DATU_BIN=/usr/local/bin/datu
USER node
EXPOSE 5176
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:5176/api/status').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.mjs"]
