# Security policy

DATU is an accountability ledger: a security bug can break the trust the
records are supposed to carry. Please report responsibly.

## Reporting a vulnerability

- Use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability"), or email the maintainers listed
  in `MAINTAINERS.md`.
- Include: affected version or commit, a description, a reproduction, and
  what an attacker gains.
- We acknowledge within 72 hours and aim to ship a fix or a written
  mitigation plan within 30 days for high severity issues.

Please do not open a public issue for an unpatched vulnerability, and do not
test against nodes you do not own.

## In scope

- The `datu` CLI and node (Rust workspace: core, store, p2p, cli, wallet,
  wallet-ffi, indexer).
- The HTTP API and embedded explorer.
- The Flutter wallet, the browser SDKs and the wallet extension.
- The deployment files in `deploy/`.

## Out of scope

- Findings that require a compromised host or a stolen device passphrase.
- Plaintext p2p transport (a recorded decision with triggers, see
  `deploy/operations/wire-privacy.md`); report TLS concerns for the HTTP
  surface instead.
- Third-party dependency advisories already covered by CI (cargo-audit,
  Trivy, SBOM gates); still welcome if we missed one.

## What is already known and documented

- The ledger is public and append-only by design; privacy depends on sealing
  fields (`PRIVACY.md`).
- Erasure is implemented as revocation; mirrors may keep copies, disclosed in
  the privacy notice.
- The node store is plaintext at rest; operators encrypt the disk
  (`deploy/operations/key-custody.md`).

## Our commitments

Signed releases with Sigstore, reproducible builds (`deploy/operations/release-signing.md`),
six CI gates including Gitleaks, Semgrep and a zero-finding compliance audit
(`compliance/`), and a public incident process (`security/security/incident-response.md`).
