# Deployment topology guidance (readiness item O4)

Who runs what, at what size, and what breaks when a piece fails. DATU has
no consensus and no mandatory roles: every node verifies everything
locally, so "topology" is about witness coverage and availability, never
about trusting a leader. Reference deployment: the demo network in
`/tmp/datu-demo` (registry + holder) and the OrangePi field box (user
manual chapter 18).

## Node kinds

| Kind | What it runs | Hardware floor | Count |
|---|---|---|---|
| Anchor/registry | `datu node --witness --every 300` + HTTP API for the namespace it governs | 1 vCPU / 1 GiB / sized per the disk model | 1+ per governed namespace |
| Witness | `datu node --witness --every N` on a store scoped with `--namespace` if space-constrained | OrangePi class | 3+ per network, on independent hosts, networks and failure domains |
| Validator/peer | `datu node` (sync + serve), policy.json gating writes | OrangePi class | as many as care |
| Explorer/mirror | `datu serve` or `datu node --http`, read-only policy | small VM | 1+ per audience |
| Projection sidecar | `datu-indexer` beside any node, SQLite/PostgreSQL/MySQL | shares the node's host | per application |

## Sizing rules

- Disk: the model in disk-growth-and-retention.md (budget the on-disk
  ~9.6 KiB/entry figure). A witness over the same namespaces as its
  anchors doubles that volume's storage across domains - that is the
  availability you are buying.
- Witnesses checkpoint on an interval; every checkpoint is ~7.5 KiB plus
  a full-verify pass over the store. `--every 300` (5 min) is a sane
  default; tighten it for high-churn namespaces, not globally.
- The 10k-entry soak ran at 147 entries/s publish on a laptop; a land
  registry doing hundreds of writes a day is nowhere near any limit.
- Browsers and dApps talk to mirrors and the wallet bridge, never to the
  p2p port.

## Connectivity

- Sync: TCP DATUP2P1 (default 7476) plus the HTTP mirror transport;
  offline via `datu delta` / `datu bundle` files over any channel.
- Discovery: seeds (`--seed host:port`), peer exchange (DATUPEX1, learned
  peers persist in `peers.json`, stale peers swept after repeated
  failures), and mDNS on the LAN (`datu discover`).
- Firewalling (field-tested on OrangePi): expose the p2p port to the
  networks you want syncing from you; keep HTTP on loopback or LAN unless
  the mirror is public; if a box hosts several clones, open each port
  deliberately (drills found 7477/7481 firewalled by default).

## Failure modes and answers

| Failure | Blast radius | Answer |
|---|---|---|
| One anchor down | Writes to its namespace pause (its key is the gate) | A second anchor admitted by policy (writers list) keeps writes flowing; or the founder re-issues. Recovery is a new node + sync, minutes. |
| One witness down | Checkpoint cadence thins | 3+ independent witnesses means coverage continues; a returning witness resyncs and checkpoints over what it now holds. |
| All witnesses of a namespace down | No fresh notarization; history keeps flowing between peers | Restore from backup (backup-restore drill) or stand up new witnesses; old checkpoints remain valid evidence. |
| Ledger data loss (disk) on one node | That node's local copy | Resync from any peer (pull-only, full verification); nothing is authoritative on any single host. |
| Network partition | Sides keep working independently; merges are ordinary sync | Append-only + local verification: no rollback ever. If the partition produced a true feed fork, the fork runbook applies. |
| Public mirror compromised | Read path only; no keys on mirrors | Replace the host; mirrors carry no write authority. |
| Wallet bridge host compromised | Full custody impact | That is incident runbook 1 (key compromise). |

## High availability, honestly

There is no cluster to keep quorate: availability = how many nodes hold
the namespaces you care about. Minimal resilient cell for one governed
namespace: 1 anchor + 3 witnesses (different networks/power) + 1 mirror +
1 offline bundle on cold storage after each anchor checkpoint. That cell
survives any single host loss with zero data loss and no write outage
(given a second admitted writer), and any two-host loss with no data loss.

## Placement guidance

- Witnesses: different ISPs/regions, not the anchor's cloud account.
- Mirrors: close to their readers (a registry's own site, a community
  portal).
- Projections: same host as their node (they read the store file; WAL
  concurrent readers are fine, the indexer never writes the node store).
- Cold evidence: after each anchor checkpoint, `datu bundle export` to
  offline media; the genesis lineage check makes tampering with bundles
  detectable.

## One explorer per cell

Every `datu serve` and every `datu node --http` exposes the full explorer UI
on its HTTP port. That is convenient on one node and confusing on five: a
pile of test runs reads as "the explorer is replicating" when it is simply
five nodes each honestly serving its own view.

Convention:

- exactly one node in a deployment serves `--http` (the anchor or mirror);
- validators and witness nodes run p2p-only (`--addr` without `--http`);
- ad-hoc test nodes are stopped when the test ends, not left listening.

`deploy/checks/observers.sh` lists every local endpoint that answers
`/v1/status`, with pid and command line, so answering "who is serving an
explorer right now" is one command. Lab sandboxes (`web/lab`) also run
`datu serve` per browser session; they bind loopback, expire on idle, and
appear in that list while a session is warm.

