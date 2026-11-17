# Wire privacy decision (readiness item S6)

Status: decided 2026-11-17, implementation deferred behind explicit
triggers. This note records what ships today, when that stops being
enough, and what exactly would be built.

## What ships today

- Native p2p sync: plaintext TCP (DATUP2P1) or plaintext HTTP.
- Integrity and authorship are transport-independent: every entry and
  checkpoint carries hybrid Ed25519 + ML-DSA-65 signatures verified
  locally by the receiver, so a man in the middle can read and drop
  traffic but cannot forge or alter a record.
- Offline channels (bundle and delta files) are protected by whatever
  the courier provides; the files verify the same way.
- Decided 2026-11-17: no QUIC. TLS-over-TCP pinned to the node Ed25519
  key is the upgrade path, only if required.

## Triggers that make confidentiality on the wire required

Any one of these:
- payloads containing personal or regulated data travel over a WAN or
  shared network (plaintext entries are readable by any on-path party);
- an enterprise procurement requires transport encryption;
- observers' metadata (which node syncs with whom, when, how much) is
  itself sensitive in the deployment context.

Not a trigger: localhost/LAN sync inside a trusted network, offline
courier channels, or the mere existence of the option.

## What would be built (implementation sketch)

1. TLS 1.3 on the native p2p listener; the server presents a
   self-signed certificate whose Ed25519 public key is the node
   identity key from `datu keys`; clients pin that key (no CA).
2. The HTTP mirror transport gets the same pinned TLS, or is documented
   as TLS-terminated by a local reverse proxy.
3. Mixed meshes: the hello/frame handshake advertises TLS capability;
   plaintext peers keep working on the open network, walled meshes can
   require TLS in `network.json`.
4. Tests the change must bring: TLS-to-TLS pull, TLS client against a
   plaintext peer refusal with a clear error, downgrade attempt refused
   on a TLS-required mesh, wrong-key peer refused (certificate pinned
   to the key, not merely trusted), witness stream exchange over TLS,
   and a soak-style lag measurement to prove the overhead cost.

## Non-goals

- Encrypting the archive at rest (that is storage's job; see
  disk-growth-and-retention.md).
- Hiding traffic shape or volume: TLS does not do this, and padding
  policy is a separate decision.
