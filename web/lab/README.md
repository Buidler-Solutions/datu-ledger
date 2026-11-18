# DATU Laboratory

An interactive manual that teaches the ledger by running one. Eight lessons
and a playground, each wired to a real `datu` node created per browser
session. Nothing is simulated: every button shells out to the release binary
an operator would run.

## Run it

```bash
# 1. the binary the sandboxes will use
cargo build --release -p datu-cli

# 2. build the frontend and start the server (serves dist/ and the API)
cd web/lab
npm ci
npm run build
npm start            # http://127.0.0.1:5175

# development: two processes, vite proxies /api to the backend
npm run dev:server   # backend on :5175
npm run dev          # frontend on :5174
```

Verification (what CI runs):

```bash
npm run build        # vite production build
npm test             # vitest + jsdom (router, curriculum, render smoke)
npm run smoke        # spawns the server, drives a full learner journey
```

## Architecture

```
web/lab
  server/index.mjs      zero-dependency Node server: sandbox lifecycle + API
  src/                  React 19 SPA (hash router, no runtime deps beyond React)
  scripts/smoke.mjs     end-to-end backend check against a real binary
```

Each sandbox is a temp directory with a freshly `init`-ed identity and a
`datu serve` process on a loopback port. Mutations run the CLI; reads proxy
the node HTTP API. Sessions are keyed by a UUID stored in `localStorage`,
expire after 30 idle minutes, and are killed (process + files) on expiry,
reset, or server shutdown.

### API

| Method | Route | Effect |
|---|---|---|
| POST | `/api/sandbox` | create a sandbox (identity + node) |
| GET | `/api/sandbox/:id` | status summary |
| GET | `/api/sandbox/:id/entries` | proxied ledger listing |
| GET | `/api/sandbox/:id/entry/:eid` | one entry with signatures |
| GET | `/api/sandbox/:id/checkpoints` | witness table |
| POST | `/api/sandbox/:id/publish` | `datu publish` |
| POST | `/api/sandbox/:id/attest` / `revoke` | `datu attest` |
| POST | `/api/sandbox/:id/checkpoint` / `verify` | `datu checkpoint` / `verify` |
| POST | `/api/sandbox/:id/bundle/export` / `import` | offline channel |
| POST | `/api/sandbox/:id/sync` | pull from another sandbox (HTTP transport) |
| DELETE | `/api/sandbox/:id` | destroy now |

## Guardrails

The backend is deliberately boring and bounded:

- 4 sandboxes per address, 64 global, 30 minute idle TTL, swept every minute
- 120 requests/minute per address; commands time out at 15 s
- namespaces and hashes are shape-checked; payloads cap at 2 KiB, claims 1 KiB
- bundles cap at 8 MiB and travel base64 in the JSON body
- `spawn` is always argument-array (no shell), and user strings never start a flag
- the server binds 127.0.0.1 only; sandboxes have no outbound peers

If you deploy this publicly, put it behind a reverse proxy with per-IP
limits and a global cap tighter than the defaults, and give the process a
dedicated unprivileged user with a scratch filesystem.

## Lessons

1. A ledger is born: genesis, identity, verification
2. Publish and read: feeds, `prev`, namespaces
3. Verify everything: content addressing, hybrid signatures
4. Trust as a graph: attestations and revocation
5. Checkpoints and witnesses: Merkle roots, fork detection
6. Two nodes, one history: bloom reconciliation, pull-only sync
7. Offline channels: bundles across air gaps
8. Forks and evidence: witness streams, `prove-fork`, exit codes

Content is distilled from the DATU user manual, which remains the complete
reference for every command, wallet flow, policy and runbook.
