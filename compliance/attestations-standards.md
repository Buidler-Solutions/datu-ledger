# Standards attestations: OWASP, CIS, NIST CSF, ISO 27001, ISO 27701

Companion to `compliance/attestations.md` (the GDPR set), same rules: every
row was reviewed by the maintainer (greenarmor) on 2026-11-20, cites the
evidence in this repository, and is recorded as an override in
`.ges/control-overrides.json`. Statuses are `pass` unless a row says
otherwise. Caveats are stated in the row, never glossed.

Reading guide, in DATU terms: there are no accounts, no passwords, no
sessions and no deletions in this system. Signing is hybrid (Ed25519 +
ML-DSA-65), identity is a public key, the ledger is the audit log, and
"deletion" is a signed revocation. Controls written for a classic web app
are translated through that lens below.

## OWASP ASVS

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| OWASP-ASVS-001 Input Validation | pass | `crates/cli/src/serve.rs` (request line/header/body limits, hex and shape validation on every route, JSON parse with typed payloads via serde), `crates/cli/tests/fuzz_lite.rs` (seeded hostile frames) | Payloads are typed documents, not free-form strings; the reader rejects anything that does not parse, and limits are checked before allocation |
| OWASP-ASVS-002 Output Encoding | pass | Explorer escapes rendered values (`esc()` in the embedded explorer), JSON serialized by serde, and every response now carries `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (`security_headers` in `serve.rs`, pinned by `responses_carry_hardening_headers`) | CSP allows only the inline explorer script (no external sources), JSON gets `default-src 'none'` |
| OWASP-ASVS-003 Authentication Security | pass | No password store exists: identity is a key pair, wallet keychain is Argon2id-encrypted (`crates/wallet/src/lib.rs`), assertions expire in 60 s and are single-use with tombstones (`crates/core/src/auth.rs`, `sdk/datu-client/src/auth.js`), submission endpoints are rate limited (`--submit-per-min`, tested in `serve.rs`) | Two factors by construction: possession of the device key plus the wallet passphrase. There is no account lockout to implement because there are no accounts |
| OWASP-ASVS-004 Access Control | pass | Write policy with trust roots, explicit writers, gated namespaces and `require_sealed` rules (`crates/store/src/policy.rs`), read-only mode refuses all admission, party roles bound per document (`crates/core/src/parties.rs`), network admission in `crates/p2p` | Deny by default: an observer admits nothing gated, a validator admits only attested writers, and forged party roles fail signature verification |
| OWASP-ASVS-005 Secrets Management | pass | GESF audit zero secrets, Gitleaks gate with a documented history allowlist (`.gitleaks.toml`), DSN passwords from the environment (`crates/indexer/src/lib.rs`), key custody and rotation (`deploy/operations/key-custody.md`, `deploy/drills/key-rotation.sh`), release signing (`deploy/operations/release-signing.md`) | No secret is committed; node keys live in `0600` files on the operator's encrypted disk and rotate by ceremony |
| OWASP-ASVS-006 Secure Communications | pass | TLS 1.2+ with HSTS at the edge (`deploy/signin-demo/Caddyfile`), Caddy in the compose stack, `deploy/operations/wire-privacy.md` (p2p plaintext decision and explicit triggers), signed assertions so authenticity does not depend on the transport | The software's HTTP API is meant to sit behind TLS; that is now enforced visibly in the deployment, and the p2p gap is a recorded decision with triggers, not an omission |

## CIS Controls

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| CIS-001 Inventory of Authorized and Unauthorized Devices | not-applicable | The project administers no device fleet; operators inventory their own hosts (`deploy/operations/topology.md` documents the deployment shape) | N/A for the software; peer identity is handled technically instead (node keys, admission, `datu discover`) |
| CIS-002 Inventory of Authorized and Unauthorized Software | pass | SPDX SBOM generated and validated in CI (`deploy/checks/spdx.py`, `web` job), CycloneDX SBOM from Syft (`sbom-scan.yml`), dependency advisory gates (cargo-audit, Trivy) | Both flavours of inventory are built from the lockfiles on every push |
| CIS-003 Secure Configuration | pass | Every compose service runs unprivileged with a read-only rootfs, `cap_drop: ALL` and `no-new-privileges`, enforced by `deploy/checks/compose-hardening.py`; hardened Dockerfiles with `USER` and `HEALTHCHECK` (verified by running the images); reproducible builds (`deploy/checks/reproducible.sh`) | Configuration is code, and the gate refuses a lax compose file in CI |
| CIS-004 Continuous Vulnerability Management | pass | CI: cargo-audit direct, Trivy dependency gate, Semgrep SAST, Gitleaks, Grype SBOM scan, GESF compliance audit; security testing drills (`deploy/drills/`), wire fuzz | Continuous, on every push and pull request; remediation lands as PRs with the gates as evidence |
| CIS-005 Controlled Use of Administrative Privileges | pass | No administrative accounts exist; containers drop all capabilities and run as fixed uids; policy changes are signed on-ledger statements (`crates/store/src/policy.rs`, `datu policy`), governance approvals are recorded in `.ges/governance-records.json` | Least privilege is the default posture; "admin action" is a signed, auditable ledger statement |

## NIST Cybersecurity Framework 2.0

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| NIST-GV-OC Organizational Context | pass | `compliance/attestations.md` (scope), `PRIVACY.md`, `.dev-logs/design/production-readiness.md` | The mission is accountable public records; the context and dependencies are written down |
| NIST-GV-RM Risk Management Strategy | pass | Governance record `gov-1795171328891-1` risk assessment, `compliance/compliance/risk-register.md`. residual-risk thresholds in the approval | Risks are scored, owned and recorded; the residual medium is accepted with named triggers |
| NIST-GV-RR Roles and Responsibilities | pass | Governance record approval (approver, authority, conditions), `security/security/incident-response.md` response roles, runbooks with owners | Single maintainer with named roles per incident phase; operators own their deployments |
| NIST-GV-PO Policy | pass | `security/security/` (7 policies), `PRIVACY.md`, `compliance/consent-management.md`, this register | The security and privacy policy set is versioned with the code and approved by the recorded approval |
| NIST-GV-OV Oversight | pass | Quarterly review cycle on the governance record (next 2027-02-20), GESF dashboard, activity log | Oversight is the review cycle plus the evidence chain, not a board |
| NIST-GV-SC Supply Chain Risk Management | pass | SBOM (SPDX + CycloneDX), Sigstore-signed releases, reproducible builds, advisory gates, `.github/workflows/dependency-scan.yml` | Dependencies are inventoried, signed and audited; releases are verifiable |
| NIST-ID-AM Asset Management | pass | Repository and `deploy/operations/topology.md` (components), SBOM for software assets, `.ges/` for governance assets | The inventory is the repo plus its generated SBOM |
| NIST-ID-RA Risk Assessment | pass | Governance record risk assessment (7.5/10, residual medium, NIST RMF style), `security/security/threat-model.md` | Threats are catalogued with mitigations and residual risk |
| NIST-ID-IM Improvements | pass | Production-readiness programme (`.dev-logs/design/production-readiness.md`), GESF recommendation channel (`.dev-logs/ai-recommendations/`), post-incident review in runbooks | Improvement is a tracked list, not an aspiration |
| NIST-PR-AA Identity Management, Authentication, Access Control | pass | Keys as identity, admission policy (`crates/p2p`), write policy (`crates/store/src/policy.rs`), single-use assertions (`crates/core/src/auth.rs`) | SSO/MFA as written assume accounts; the equivalent here is key-based identity with policy-gated writes |
| NIST-PR-AT Awareness and Training | not-applicable | Single-maintainer project; operator onboarding is the manuals (`docs/`, `.dev-logs/manuals/`) | N/A as a programme; the manuals serve as the training material for operators |
| NIST-PR-DS Data Security | pass | Hybrid signatures, sealed fields, TLS at the edge (`deploy/signin-demo/Caddyfile`), classification rules (`compliance/compliance/data-inventory.md`), wallet keystore (Argon2id) | Encryption at rest is sealing plus operator disk encryption (`key-custody.md`); in transit is TLS at the edge |
| NIST-PR-PS Platform Security | pass | Hardened images and compose (`deploy/checks/compose-hardening.py`), CIS-Docker pack controls, read-only rootfs, no capabilities | The platform baseline is enforced by the compose gate on every push |
| NIST-PR-IR Technology Infrastructure Resilience | pass | `datu bundle export/import`, backup and crash drills, `deploy/operations/recovery-flows.md`, witness checkpoints | Resilience is replication plus replayable evidence; RTO/RPO are documented per operator |
| NIST-DE-CM Continuous Monitoring | pass | `datu watch` (revocations), CI gates on every push, advisory feeds, `datu verify` | Monitoring is the ledger's own state plus CI; there is no SIEM because there is no SOC, and the attestation says so |
| NIST-DE-AE Adverse Event Analysis | pass | Fork drills and evidence (`crates/core/src/fork.rs`, `deploy/drills/fork-drill.sh`), conflict listing (`/v1/conflicts`), denied-sync counters | Divergent histories are detected and preserved as evidence, not resolved silently |
| NIST-RS-MA Incident Management | pass | `security/security/incident-response.md` (P1-P4, phases), `deploy/operations/incident-runbooks.md` (four runbooks with owners) | The process is written, with the ledger's own evidence steps (key compromise runbook) |
| NIST-RS-AN Incident Analysis | pass | Runbook evidence sections, checkpoints and bundles as forensic material, `datu verify`, provenance `first_seen` | Evidence preservation is native: entries are signed and immutable |
| NIST-RS-CO Incident Response Reporting and Communication | pass | 72-hour authority notification and data-subject templates (`security/security/incident-response.md`), `datu watch` for affected keys | Communication has a protocol channel: the ledger reports revocations to the affected key |
| NIST-RS-MI Incident Mitigation | pass | Key-compromise runbook (`attest revoke --key`), guardian recovery, drills (`key-rotation.sh`, `watch-revoke.sh`) | Containment is a statement plus recovery ceremony, practised in CI |
| NIST-RS-IM Incident Response Improvements | pass | Post-incident review step in the response plan; lessons feed the readiness matrix and the GESF recommendation channel | Reviews are written into the same documents the drills exercise |
| NIST-RC-RP Recovery Plan Execution | pass | `deploy/drills/backup-restore.sh`, `crash-recovery.sh`, `deploy/operations/recovery-flows.md` (RTO/RPO per operator), bundle format | Recovery is exercised in CI, not on paper only |
| NIST-RC-CO Recovery Communication | pass | Recovery-flows doc names who communicates what; incident templates cover stakeholder groups | Operators communicate; the software provides the evidence trail |

## ISO 27001

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| ISO27001-A5 Information Security Policies | pass | `security/security/` policy set, `PRIVACY.md`, recorded approval in `.ges/governance-records.json` | Policies are versioned documents with a named approver and review cycle |
| ISO27001-A6 Organization of Information Security | pass | Governance record roles and approval authority, incident response roles, runbook owners | A single-maintainer organisation with explicit, recorded responsibilities |
| ISO27001-A8 Asset Management | pass | Repository, SBOM (SPDX + CycloneDX), `deploy/operations/topology.md`, `.ges/` governance assets | Assets are code, generated inventories and the governance record |
| ISO27001-A9 Access Control | pass | Write policy and admission (`crates/store/src/policy.rs`, `crates/p2p`), read-only mode, non-root containers, no admin accounts | Least privilege is the only posture; grants are signed statements |
| ISO27001-A10 Cryptography | pass | Hybrid Ed25519 + ML-DSA-65 (`crates/core/src/entry.rs`), Argon2id keystore and AES-GCM sealing (`crates/wallet`), `deploy/operations/key-custody.md` | The cryptographic policy is the code plus the custody doc; algorithms are named and versioned |
| ISO27001-A12 Operations Security | pass | `deploy/operations/` (runbooks, retention, retention and topology), reproducible builds, no-NUL and compose gates | Operations are documented procedures checked in CI where automatable |
| ISO27001-A14 System Acquisition, Development and Maintenance | pass | CI gates on every push (tests, clippy -D warnings, rustdoc, semgrep, gitleaks, SBOM, compliance), review in PRs, reproducible release builds | Security is a merge gate, and releases are byte-reproducible |
| ISO27001-A16 Incident Management | pass | `security/security/incident-response.md`, `deploy/operations/incident-runbooks.md`, drills | Same process as NIST-RS; evidence is the drill runs |
| ISO27001-A17 Business Continuity | pass | backup/crash drills, bundle format, `deploy/operations/recovery-flows.md` (RTO/RPO), witness checkpoints | Continuity is replayable evidence; operators define RTO/RPO |
| ISO27001-A18 Compliance | pass | This register, `compliance/legal-bases.json` with its CI gate, GESF audit at zero findings | Compliance is tracked as artefacts with gates, not as a claim |

## ISO 27701 (privacy)

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| ISO27701-5.2 Information Privacy Policies | pass | `PRIVACY.md`, `compliance/consent-management.md`, `compliance/legal-bases.json` | The notice and register are the privacy policy, versioned with the code |
| ISO27701-5.3 Roles and Responsibilities for PII | pass | `PRIVACY.md` (software vs operator/controller), governance record, `compliance/consent-management.md` | The project ships software, not a service: operators are the controllers and appoint their own DPO where required |
| ISO27701-5.4 Privacy Risk Assessment | pass | `compliance/compliance/privacy-impact-assessment.md`, governance record risk assessment, `security/security/threat-model.md` | PIA/DPIA exists for the design; operators extend it per deployment |
| ISO27701-6.2 PII Identification and Classification | pass | `compliance/legal-bases.json` (categories per activity), `compliance/compliance/data-inventory.md` (DATU section) | Classified by where it lives: public statements vs sealed fields vs local-only notes |
| ISO27701-6.4 PII De-identification and Anonymization | pass | Keys as identifiers, sealing utilities, `first_seen` local-only note | Pseudonymisation is structural: the ledger knows keys, not names, unless a registry states one |
| ISO27701-6.5 PII Segregation | pass | Sealed payloads stay in the operator database; the ledger holds statements and ciphertext; `first_seen` never leaves the node | Segregation is by design: personal content does not travel with the public record |
| ISO27701-6.7 PII Retention and Disposal | pass | `compliance/compliance/retention-policy.md` (append-only section), `deploy/operations/disk-growth-and-retention.md` | Retention is indefinite by design; disposal is revocation plus never publishing, with residual mirrors disclosed |
| ISO27701-6.9 PII Transfer Controls | pass | `PRIVACY.md` (global public ledger, cross-border disclosed), `deploy/operations/wire-privacy.md` | Transfers are inherent to a public ledger; the notice states it and operators assess their own Chapter V position |
| ISO27701-7.3 PII Controller Obligations | pass | Consent ceremonies (`crates/core/src/enroll.rs`), `datu consent` register, rights section in `PRIVACY.md` | Consent capture and rights are protocol features; the register proves what was consented to |
| ISO27701-7.5 PII Processor Obligations | not-applicable | The project is not a processor and signs no DPAs; an operator acting as a processor documents its own instructions and DPAs (ROPA third-party section) | N/A for the software |
| ISO27701-8.4 Privacy by Design | pass | DPIA, defaults reviewed, sealing-first posture, consent-at-the-door, `PRIVACY.md` | Privacy reviews ride the normal design process; the readiness programme records them |

## CIS Docker Benchmark

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| CIS-DOCKER-001 Run Container as Non-Root User | pass | Both Dockerfiles create and switch to a dedicated uid (`USER datu`, `USER node`); compose services pin the same uid; proven by running the validator image (`uid=10001(datu)`) | Non-root is the only mode shipped |
| CIS-DOCKER-002 Use Trusted Base Images Only | pass | Official images only (`rust`, `debian`, `node`, `caddy`, `postgres`), each pinned by digest; the compose gate refuses untrusted or unpinned references | Base image bytes cannot change under us |
| CIS-DOCKER-003 Do Not Use :latest Tag | pass | Every `FROM` and `image:` carries a version tag plus `@sha256:` digest; `deploy/checks/compose-hardening.py` fails on untagged or unpinned images | Pinned twice: tag for humans, digest for the build |
| CIS-DOCKER-004 Set Memory Limits | pass | `mem_limit` on every compose service (128m-512m per role); the gate requires it | Bounded blast radius per container |
| CIS-DOCKER-005 Set CPU Limits | pass | `cpus` on every compose service (0.25-1.0); the gate requires it | A runaway indexer cannot starve the node |
| CIS-DOCKER-006 Read-Only Root Filesystem | pass | `read_only: true` on every compose service, with `tmpfs` only where a process needs scratch space (including postgres's socket dir); the gate requires it | Containers cannot write to their own image |
| CIS-DOCKER-007 No Privileged Containers | pass | `privileged: false` stated explicitly on every service; the gate fails on `privileged: true` | Proven by configuration and by the gate, not by absence alone |
| CIS-DOCKER-008 Drop Dangerous Capabilities | pass | `cap_drop: [ALL]` everywhere; the gate requires it | Postgres runs with all capabilities dropped and its own uid (verified) |
| CIS-DOCKER-009 Use HEALTHCHECK Instruction | pass | `HEALTHCHECK` in both Dockerfiles (datu status for the node/indexer, an HTTP probe for the dapp), plus compose healthchecks for postgres | Liveness is declared, not assumed |
| CIS-DOCKER-010 Pin Image Digests (SHA256) | pass | `rust`, `debian`, `node`, `caddy` and `postgres` referenced by `@sha256:` in Dockerfiles and compose; the gate requires a digest | Supply-chain pinning is enforced in CI |

## Philippines DPA (RA 10173, IRR)

| Control | Status | Evidence | DATU reading |
|---|---|---|---|
| DPA-PH-01 PIC and PIP Designation | pass | `compliance/legal-bases.json` (role split per activity), `PRIVACY.md` (software vs operator), consent ceremonies | The operator is the PIC for what it publishes; the software is a tool, never a PIP, and the register states this |
| DPA-PH-02 Data Protection Officer (Philippines) | not-applicable | No organisation is run by this repository; the DPO is designated by each PIC | An open-source project cannot appoint an NPC DPO; operators do |
| DPA-PH-03 NPC Registration | not-applicable | No personal-data processing organisation behind the code; the 1,000-data-subject threshold is an operator question | N/A for the software; a PH operator registers its own systems |
| DPA-PH-04 Criteria for Lawful Processing | pass | `compliance/legal-bases.json` carries the DPA 2012 counterpart per activity (Sec. 12(a)-(c), 13), validated in CI; consent ceremonies (`crates/core/src/enroll.rs`) | Lawful criteria are article-cited against the code, not asserted |
| DPA-PH-05 Data Subject Rights (Philippines) | pass | `datu consent` (information/access), revocation (objection/erasure), bundle export (portability), `PRIVACY.md` rights section | Rights are protocol verbs, and the notice says how each one works |
| DPA-PH-06 Security Measures (NPC Circular 16-03) | pass | Organisational: policies in `security/security/`, incident plan, approvals. Physical/technical: non-root pinned containers, sealed fields, hybrid signatures, access policy (`crates/store/src/policy.rs`), CI audits | The circular's three pillars are the policy set, the hardened runtime and the audited build |
| DPA-PH-07 Privacy Impact Assessment | pass | `compliance/compliance/privacy-impact-assessment.md`, governance risk assessment, `security/security/threat-model.md` | PIA exists for the design; operators extend it per deployment |
| DPA-PH-08 NPC Breach Notification | pass | Regulator matrix in `security/security/incident-response.md` (NPC, 72 hours, sensitive personal information or identity-fraud risk), templates, `datu watch` as the subject-facing channel | The procedure names the NPC explicitly; notification itself is the PIC's act |
| DPA-PH-09 Data Sharing and Outsourcing | not-applicable | The project shares no personal data and outsources nothing; operators execute their own sharing agreements | N/A for the software |
| DPA-PH-10 Cross-Border Transfers (Philippines) | pass | `PRIVACY.md` global-ledger disclosure, cross-border responsibility per activity in `legal-bases.json`, the comparability duty restated for operators | A public ledger is global by nature; the notice and register say so, and the operator assesses comparability for its deployment |

## Scope decision: which packs the software attests, and which belong to operators

GESF counts `not-applicable` together with `pass` in the score, so the honest
question is not "can this be made green" but "does this control belong to the
software at all". This is the line we drew:

| Pack | Attested by the project | Why |
|---|---|---|
| GDPR | yes | The protocol processes personal data (keys, attestations, sealed fields); every control maps to code, a notice, a register or a drill |
| OWASP ASVS | yes | The HTTP surface, the wallet and the SDK are this project's code |
| CIS Controls | yes (CIS-001 N/A) | SBOM, secure configuration, vulnerability management and privilege are all code-side; device inventory is not ours |
| NIST CSF 2.0 | yes (PR-AT N/A) | Governance, risk, identity, monitoring, incident and recovery are written and drilled; a training programme needs employees |
| ISO 27001 | yes | The information security management controls map to policies, gates and drills in the repository |
| ISO 27701 | yes (7.5 N/A) | Privacy controls are protocol features; "processor obligations" need a party that is a processor, which the project is not |
| privacy-core | yes (11 N/A) | Attested in compliance/attestations-privacy-core.md. The software-side controls (inventory, consent, rights, security, incident, retention, minimisation) carry evidence; the organisation-side ones (DPO, staff training, vendor DPAs, SCCs, localisation) are marked not-applicable with the reason, because they belong to an operator with staff and vendors |
| CIS-Docker | yes | The project ships the images and compose files; every control is now enforced in the build or by `deploy/checks/compose-hardening.py` |
| CIS-Kubernetes | no | There is no Kubernetes deployment in this repository; the pack describes infrastructure this project does not ship |
| DPA-PH | yes (3 N/A) | The software-side duties (lawful criteria, rights, security measures, PIA, 72-hour NPC notification, cross-border disclosure) map to registers, ceremonies and runbooks; designation, NPC registration and data-sharing agreements are acts only an operator can perform |

The dashboard will therefore show privacy-core, CIS-Kubernetes and DPA-PH at
0%: that is a scoping statement, not an unaddressed gap. Operators complete
those packs for their own deployments, which is where the legal duties
actually live.

## Standing rule

Same as the GDPR set: evidence above, reviewer named, overrides versioned in
`.ges/control-overrides.json`. If the evidence stops being true, the
attestation is withdrawn in the same change.
