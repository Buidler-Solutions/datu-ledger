# Control review checklist (human attestation step)

GESF scores *attested* controls. The automated audit is clean (zero
findings across secrets, injection, crypto, container and config rules), and
the technical controls below are implemented in the codebase - but the tool
deliberately leaves them "not implemented" until a human attests each one
with a pointer to its evidence. The AI assistant that prepared this file did
not, and must not, mark controls as pass.

## How to attest a control

```bash
ges control GDPR-ART32-002 pass     # after you have read the evidence
ges control <CONTROL-ID> not-applicable   # when the control truly does not apply
ges audit                            # rescore; the badge/report picks it up
```

Attest only what you can point at. Anything you cannot evidence yet is
better left "not implemented" than marked done.

## Evidence map (control family -> where the evidence lives)

| Control family | Evidence in this repository |
|---|---|
| Encryption at rest / in transit | `crates/wallet` (encrypted keychain, Argon2id), `crates/core/src/pq.rs` (hybrid Ed25519 + ML-DSA-65), sealed fields (`signet seal`, `seal-deferred`); transport posture and triggers in `deploy/operations/wire-privacy.md` |
| Authentication / unique identity | SignetAuth (`crates/core/src/auth.rs`, `sdk/datu-client/src/auth.js`), `specs/signetauth.md`, phone sign-in in `apps/wallet`, single-use nonce tombstones |
| Authorization / writer policy | `crates/store/src/policy.rs` (attestors, min_cosigners, gated namespaces), `crates/cli/src/main.rs` policy commands, drills in `deploy/drills/` |
| Audit trail / integrity | Append-only DAG entries with hybrid signatures, witness checkpoints (`crates/core/src/checkpoint.rs`), fork evidence, `datu verify`, `datu watch` |
| Pseudonymisation / minimisation | Keys as identifiers; `first_seen` provenance never synced or served; sealing guidance in `crates/wallet` and `deploy/operations/sealing-retention-gdpr.md` |
| Retention / storage limitation | `compliance/compliance/retention-policy.md` (DATU section: append-only, revocation as erasure, sealing), `deploy/operations/disk-growth-and-retention.md` |
| Data subject rights | Revocation (`datu attest revoke`), guardian recovery (`datu enroll recover`), sealing; ROPA addendum in `compliance/compliance/processing-records.md` |
| Incident management | `security/security/incident-response.md`, `deploy/operations/incident-runbooks.md`, key-compromise runbook + `deploy/drills/key-rotation.sh` |
| Backup / disaster recovery | `deploy/drills/backup-restore.sh`, `deploy/drills/crash-recovery.sh`, `datu bundle export/import`, `deploy/operations/recovery-flows.md` |
| Supply chain | `deploy/checks/spdx.py` (SPDX SBOM, denied licenses), cargo-audit gate in `ci.yml`, `.github/workflows/sbom-scan.yml`, `deploy/operations/release-signing.md` (Sigstore + reproducibility) |
| Container hardening | `deploy/checks/compose-hardening.py` (CI gate), hardened Dockerfiles (`USER`, `HEALTHCHECK`), compose files with `user:`, `read_only`, `cap_drop: ALL`, `no-new-privileges` |
| Secrets management | Zero secrets in tracked files; DSNs take passwords from the environment (`crates/indexer`), `.gitleaks.toml` allowlists only throwaway CI history |
| Privacy governance | Governance record `gov-1795171328891-1` in `.ges/governance-records.json` (risk assessment, policy basis, conditional approval, review cycle, data inventory, compliance links), verified complete by `ges governance verify` |
| Consent | Two-signature enrollment (`datu enroll`) and guardian recovery; party signatures in `crates/core/src/parties.rs` |

## Known limitations to disclose in any attestation

- The ledger is public by design. Privacy depends on operators sealing
  personal payloads; this is documented, not enforced by the protocol.
- Wire transport is plaintext TCP today, a recorded decision with explicit
  triggers (`deploy/operations/wire-privacy.md`).
- GESF scanner false positives are documented in `.gesignore` with the
  upstream recommendations filed under `.dev-logs/ai-recommendations/`.
