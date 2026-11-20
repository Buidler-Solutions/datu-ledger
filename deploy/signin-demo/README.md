# Deploying the sign-in demo

Three containers: a validator node (`datu serve`, read-only), the relying
party (`web/signin-demo`), and Caddy for automatic TLS.

## On a fresh VPS

```bash
git clone https://github.com/greenarmor/datu-ledger && cd datu-ledger
# point demo.example.com at this box, then:
cd deploy/signin-demo
sed -i 's/demo.example.com/your.domain/' Caddyfile
docker compose up -d --build
```

The build is a two-target Dockerfile: the workspace compiles once in a
`rust` stage (cargo target and registry are cached as BuildKit mounts), and
both runtime images take the binary from there. Every service runs
unprivileged with a read-only root filesystem, `cap_drop: ALL`, and
`no-new-privileges`; Caddy runs as its own user on ports 8080/8443, mapped
to 80/443, so TLS needs no low-port capability.

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
