# Deploying the sign-in demo

Three containers: a validator node (`datu serve`, read-only), the relying
party (`web/signin-demo`), and Caddy for automatic TLS.

## On a fresh VPS

```bash
git clone https://github.com/greenarmor/datu-ledger && cd datu-ledger
cargo build --release -p datu-cli        # once, the compose file mounts the binary
# point demo.example.com at this box, then:
cd deploy/signin-demo
sed -i 's/demo.example.com/your.domain/' Caddyfile
docker compose up -d
```

First build of the validator container compiles the workspace inside
`rust:1.96.0`; if that is too slow for your taste, build the binary on the
host (as above) and replace the validator service with the same `node:22`
image pattern the demo uses.

## What the demo exercises once deployed

- RSA/TLS termination by Caddy, plain HTTP inside the compose network.
- The verifier is the release `datu` binary: `datu signet auth-verify`.
- The attestation panel reads `identity.attest` from the validator. To see a
  claim, attest the phone key from the validator's identity:

```bash
docker compose exec validator /src/target/release/datu \
  --data-dir /data attest create \
  --subject <phone-ed25519-pubkey> \
  --claims '{"role":"clerk","legal_name":"Example Registry"}'
```

## Hardening before this is a real dApp

- Issue a session (cookie or short-lived JWT) bound to the verified pubkey;
  the demo stops at the verified identity.
- Store registered pubkeys; treat unknown keys as "signed in, unattested"
  rather than rejecting silently.
- Rate-limit `GET /` (it mints challenges) and cap the open-challenge map.
- Serve the app from the same origin as the callback, as the demo does; a
  different origin for the callback is a design change, not a flag.
