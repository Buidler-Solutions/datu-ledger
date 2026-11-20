# Control attestations (GDPR-tagged set)

Every control below was attested by the maintainer (greenarmor) on
2026-11-20 after reviewing the evidence named in the row. This file is the
human-review record; GESF reads the statuses from
`.ges/control-overrides.json`. Two rows carry explicit caveats because the
property is provided at deployment time, not by the software; they are
attested with that caveat stated, not silently.

| Control | Status | Evidence | Caveat / note |
|---|---|---|---|
| BC-001 Cryptographic Signatures | pass | `crates/core/src/entry.rs` (Ed25519 + ML-DSA-65 hybrid, signing over canonical body bytes), `crates/core/tests/` | none |
| BC-002 Validator Identity Verification | pass | `crates/p2p` hello/network policy, `crates/p2p/tests/network_admission_test.rs`, CLI network/policy commands | none |
| BC-003 Key Rotation | pass | `deploy/drills/key-rotation.sh`, `deploy/operations/key-custody.md` | none |
| BC-004 Encrypted Payload Support | pass | `crates/wallet/src/lib.rs` (`seal`, `seal-deferred`, `release-deferred`), `deploy/operations/sealing-retention-gdpr.md` | none |
| BC-005 Immutable Audit Trails | pass | Append-only store (`crates/store`), witness checkpoints (`crates/core/src/checkpoint.rs`), `datu verify`, `datu watch` | none |
| BC-006 No Plaintext Personal Data On-Chain | pass | `crates/store/src/policy.rs` (`require_sealed` rules, gated namespaces), `PRIVACY.md`, `compliance/consent-management.md` | Identity statements (labels/claims) are intentional public statements by design; payloads are sealed or omitted, and `require_sealed` enforces it per namespace on validators |
| GDPR-ART5-001 Lawfulness, Fairness, Transparency | pass | `PRIVACY.md`, `compliance/legal-bases.json` + `deploy/checks/legal-bases.py`, `datu consent` (`crates/core/src/consent.rs`) | none |
| GDPR-ART5-002 Purpose Limitation | pass | `compliance/legal-bases.json` (purpose and basis per activity), gated namespaces (`crates/store/src/policy.rs`), `compliance/consent-management.md` | none |
| GDPR-ART5-003 Data Minimisation | pass | Keys-only identifiers, `first_seen` never synced or served, sealing guidance, `PRIVACY.md` | none |
| GDPR-ART5-004 Accuracy | pass | Signed statements with supersession (`identity.attest` plus revocation as new statements, `crates/core/src/attest.rs`), `datu attest status`, `datu consent` | none |
| GDPR-ART5-005 Storage Limitation | pass | `compliance/compliance/retention-policy.md` (append-only section), `deploy/operations/disk-growth-and-retention.md` | none |
| GDPR-ART5-006 Integrity and Confidentiality | pass | Hybrid signatures, checkpoints/merkle, sealing, policy (`crates/store/src/policy.rs`), `deploy/operations/wire-privacy.md` | none |
| GDPR-ART25-001 Data Protection by Design | pass | `compliance/compliance/privacy-impact-assessment.md`, `security/security/threat-model.md`, the production-readiness programme in `.dev-logs/design/production-readiness.md` | none |
| GDPR-ART25-002 Data Protection by Default | pass | Minimal default payloads, sealing utilities, no accounts or analytics (`PRIVACY.md`), defaults reviewed in `crates/wallet` and `crates/cli` | none |
| GDPR-ART30-001 Record of Processing Activities | pass | `compliance/compliance/processing-records.md` + `compliance/legal-bases.json` | none |
| GDPR-ART30-002 Processor Records | pass | ROPA "Third-Party Processors" section (none in the software; operators document their own) plus recipients per activity in `compliance/legal-bases.json` | Deployment-dependent: operators must list their own processors |
| GDPR-ART32-001 Pseudonymisation | pass | Keys as identifiers throughout (`PRIVACY.md`), no account PII, sealing for the rest | none |
| GDPR-ART32-002 Encryption at Rest | pass | Wallet keystore (Argon2id + encrypted keychain, `crates/wallet/src/lib.rs`), field-level sealing, `deploy/operations/key-custody.md` (encrypted disk requirement) | The node store itself is plaintext files: at-rest protection relies on the operator's disk encryption, stated in key-custody.md |
| GDPR-ART32-003 Encryption in Transit | pass | TLS terminated in front of every HTTP surface (`deploy/signin-demo/docker-compose.yml` + Caddyfile), `deploy/operations/wire-privacy.md` (decision and triggers), signed assertions in SignetAuth (`crates/core/src/auth.rs`) | The p2p transport is plaintext TCP by recorded decision; operator deployments terminate TLS at the edge |
| GDPR-ART32-004 Unique User Identification | pass | Ed25519/ML-DSA-65 keys as the sole identifier (`crates/core/src/auth.rs`, `crates/core/src/entry.rs`) | none |
| GDPR-ART32-005 Automatic Session Timeout | pass | Assertion TTL 60 s and single-use nonce tombstones (`sdk/datu-client/src/auth.js`, `crates/core/src/auth.rs`), wallet idle lock (`apps/wallet/lib/presentation/screens/shell_screen.dart`) | none |
| GDPR-ART32-006 Audit Logging | pass | Append-only entries with timestamps, witness checkpoints, `datu watch`, node request logs (`crates/cli/src/serve.rs`) | none |
| GDPR-ART32-007 Integrity Controls | pass | Signatures, merkle checkpoints, `datu verify`, fork evidence (`crates/core/src/fork.rs`), `deploy/drills/fork-drill.sh` | none |
| GDPR-ART32-008 Backup and Recovery | pass | `datu bundle export/import`, `deploy/drills/backup-restore.sh`, `deploy/drills/crash-recovery.sh`, `deploy/operations/recovery-flows.md` | none |
| GDPR-ART32-009 Regular Security Testing | pass | Seven CI drills (`deploy/drills/`), wire fuzz (`fuzz_lite`), Semgrep/Gitleaks/Trivy/SBOM gates, GESF audit gate | none |
| GDPR-ART33-001 Breach Notification to Authority | pass | `security/security/incident-response.md` (72-hour procedure), `deploy/operations/incident-runbooks.md` (owners, detect/contain/recover/evidence) | Operator-executed: the operator is the controller and notifies |
| GDPR-ART33-002 Breach Documentation | pass | Incident-response breach register section plus evidence sections in `deploy/operations/incident-runbooks.md` | Operator-executed |
| GDPR-ART34-001 Breach Communication to Data Subjects | pass | Notification templates (`security/security/incident-response.md`), plus ledger-native notification (`datu watch` reports revocations to the affected key) | Operator-executed |
| GOVP-001 System Registration | pass | Governance record `gov-1795171328891-1` (`.ges/governance-records.json`) | none |
| GOVP-002 Risk Assessment Requirement | pass | Record `risk_assessment` (score 7.5/10, residual medium) | none |
| GOVP-003 Policy Basis Documentation | pass | Record `policy_basis` (DATU-PRIV-001 v1.0, GDPR) | none |
| GOVP-004 Approval Authority Chain | pass | Record `approval` (conditional, valid 2026-11-20 to 2027-11-20) | none |
| GOVP-005 Evidence Chain Completeness | pass | 13 evidence references, `ges governance verify` = VALID | none |
| GOVP-006 Committee Approval Record | not-applicable | No committee exists: the project is single-maintainer and approval is recorded with the named approver and authority under GOVP-004 | Marked N/A rather than inventing a committee |
| GOVP-007 Review Cycle Monitoring | pass | Record `review_cycle` (quarterly, next 2027-02-20) | none |
| GOVP-008 Approval Expiry Enforcement | pass | Approval carries `valid_until`; `ges governance verify` and the dashboard report expiry state | none |
| GOVP-009 Data Inventory for Governance | pass | Record `data_inventory` plus `compliance/compliance/data-inventory.md` (DATU section) | none |
| GOVP-010 Compliance Framework Mapping | pass | Record `compliance` links plus the installed packs (`controls/`) | none |
| GOVP-011 Provenance Chain Verification | pass | `ges governance verify <id>` = VALID, chain Approval -> Risk -> Policy -> Evidence -> Review | none |
| GOVP-012 Dashboard Auditor Access | pass | `ges dashboard` (`/api/data`, `/health`) renders score, controls, findings, governance and the activity log | none |

## How the generic controls read in a DAG accountability ledger

DATU is not a SaaS: there are no accounts, no cookies, no sessions table,
and nothing is ever deleted. Several GDPR controls assume that shape, so
here is the translation this register attests against:

- **Erasure vs storage limitation (Art. 5(1)(e), 17).** The ledger is
  append-only and mirrored by design. "Deletion" is not a primitive:
  erasure is a signed `identity.revoke` statement plus never publishing
  personal payloads, with residual mirror copies disclosed (Art. 17(2)).
  The retention documents and `PRIVACY.md` state this plainly.
- **Records of processing (Art. 30).** One register
  (`compliance/legal-bases.json`) covers the protocol activities; each
  operator copies and amends it for its own deployment. There are no
  processors inside the software (Art. 30(2)); an operator's own
  processors belong in its copy.
- **Pseudonymisation and identification (Art. 32(1), 32(4)).** The
  identifier is the public key. There is no separate account id to leak,
  and no password store to breach; the wallet keeps keys encrypted on the
  device (Argon2id keychain).
- **Encryption at rest and in transit (Art. 32(2), 32(3)).** Sealed
  fields and the wallet keystore are software-level; the node store and
  the wire are operator-level (disk encryption in `key-custody.md`, TLS
  terminated in front of the HTTP surface; the p2p transport decision and
  its triggers are in `wire-privacy.md`). Attested with those caveats.
- **Session timeout (Art. 32(5)).** There is no session to time out in
  the protocol: assertions expire in 60 seconds and are single-use, and
  the wallet locks itself when idle. Relying parties hold the only
  session, under their own policy.
- **Audit logging and integrity (Art. 32(6), 32(7)).** The ledger is the
  audit log: every entry is signed, hash-chained and covered by witness
  checkpoints; `datu verify` and fork evidence prove integrity.
- **Breach notification (Art. 33, 34).** Detection and notification are
  operator duties (runbooks, 72-hour procedure, templates); the ledger
  adds a native channel: `datu watch` tells the affected key when a
  statement about it is revoked.
- **On-chain personal data (BC-006).** Identity statements (label, legal
  name, role) are deliberate public statements, because accountability
  needs a name attached to a key. Everything else about a person is
  sealed or omitted, and validators can require sealed fields per
  namespace (`require_sealed`).
- **Governance provenance (GOVP).** The record chain itself is the
  evidence: system -> risk -> policy -> approval -> evidence -> review,
  verified by `ges governance verify`. A committee record (GOVP-006) is
  marked not applicable: this is a single-maintainer project, and the
  named approver and authority are recorded in the approval instead.

## Standing rule

Attestations are made against the evidence above, by the named reviewer,
and recorded as overrides in `.ges/control-overrides.json` (versioned with
the code). If the evidence stops being true, the attestation must be
withdrawn in the same change; CI keeps the automated audit at zero findings
either way.
