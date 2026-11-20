# PRIVACY-CORE attestations (translated for a DAG accountability ledger)

Same rules as the other registers: reviewed by the maintainer (greenarmor) on
2026-11-20, evidence cited from this repository, recorded in
`.ges/control-overrides.json`. Privacy-core assumes an organisation with
employees, vendors and servers; DATU is an open-source protocol and wallet.
The organisation controls are translated below, and the ones that need an
employer, a vendor relationship or a regulator filing are marked
not-applicable with the reason, because those duties sit with each operator
(the controller). GESF counts not-applicable as passed, so the split is
stated here explicitly rather than hidden in the score.

| Control | Name | Status | Evidence | DATU reading |
|---|---|---|---|---|
| PRIV-GOV-01 | Privacy Program | pass | Governance record gov-1795171328891-1 (scope, objectives, approval, review cycle), the compliance set, these registers | The charter is the governance record plus the attestation registers; scope is the software and its deployments |
| PRIV-GOV-02 | Privacy Policies | pass | PRIVACY.md, compliance/consent-management.md, compliance/legal-bases.json | Policies are versioned with the code |
| PRIV-GOV-03 | Data Protection Officer | not-applicable | The project is software, not a service; PRIVACY.md names operators as controllers | No DPO is appointed by an open-source project; each operator appoints one where the law requires it |
| PRIV-GOV-04 | Privacy Risk Management | pass | privacy-impact-assessment.md, governance risk assessment (7.5/10, residual medium), threat-model.md | NIST RMF style method with named residual risk and triggers |
| PRIV-GOV-05 | Management Review | pass | Quarterly review cycle on the governance record (next 2027-02-20); attestation registers updated with evidence | Review is scheduled and recorded |
| PRIV-INV-01 | Data Inventory Register | pass | compliance/legal-bases.json (categories per activity), data-inventory.md DATU section | Machine-readable and gate-checked in CI |
| PRIV-INV-02 | Data Flow Mapping | pass | PRIVACY.md (what can appear, what never does), recipients per activity, deploy/operations/topology.md | Flows: device to node to mirrors; sealed fields never leave the operator database |
| PRIV-INV-03 | Processing Activity Records | pass | processing-records.md plus the ten registered activities | ROPA tailored to the append-only reality |
| PRIV-INV-04 | System Classification | pass | Classification rules in data-inventory.md | Four levels with encryption and access requirements |
| PRIV-CNS-01 | Consent Collection | pass | Enrollment and recovery ceremonies (crates/core/src/enroll.rs), party signatures, datu consent | Consent is a signature bound to role and key |
| PRIV-CNS-02 | Consent Withdrawal | pass | identity.revoke, guardian recovery, datu watch notification, PRIVACY.md | Withdrawal is a statement; the affected key is told |
| PRIV-CNS-03 | Legal Basis Documentation | pass | compliance/legal-bases.json with deploy/checks/legal-bases.py | Articles cited and enforced against the code in CI |
| PRIV-CNS-04 | Purpose Limitation | pass | Per-activity purpose in legal-bases.json; gated namespaces and require_sealed (crates/store/src/policy.rs) | Purpose is a policy gate |
| PRIV-DSR-01 | Right of Access | pass | datu consent, datu attest status, /v1/identity/{key}, /v1/entries, datu bundle export | Access is native to the ledger |
| PRIV-DSR-02 | Right to Rectification | pass | Superseding attestations, revocation as new statements (attest.rs) | Correction is a new signed statement |
| PRIV-DSR-03 | Right to Erasure | pass | identity.revoke (attestation or key), sealing going forward, PRIVACY.md Art. 17(2) disclosure | Revocation plus omission; residual mirrors disclosed |
| PRIV-DSR-04 | Right to Data Portability | pass | datu bundle export/import (self-verifying format), JSON APIs | Portability is the bundle |
| PRIV-DSR-05 | Right to Object | pass | Stop-publishing path in PRIVACY.md, revocation, runbooks | Objection means the operator stops publishing and revokes |
| PRIV-DSR-06 | Automated Decision Review | not-applicable | No profiling or automated decisions; admission is deterministic policy | Nothing decides about people automatically |
| PRIV-SEC-01 | Access Management | pass | Write policy and admission (policy.rs, crates/p2p), non-root containers, compose gate | Least privilege is the only posture |
| PRIV-SEC-02 | Encryption | pass | Field-level sealing (AES-GCM, crates/wallet), Argon2id keystore, TLS 1.2+ with HSTS at the edge | Caveat: node store relies on operator disk encryption (key-custody.md) |
| PRIV-SEC-03 | Pseudonymisation and Anonymisation | pass | Keys as identifiers, sealing, first_seen local-only, datu consent | The ledger holds pseudonyms by construction |
| PRIV-SEC-04 | Secure Development | pass | DPIA and privacy reviews, CI gates (audit, semgrep, gitleaks, SBOM, compliance), design logs | Privacy rides the same gates as security |
| PRIV-INC-01 | Incident Response Plan | pass | incident-response.md (P1-P4, five phases), incident-runbooks.md with owners and evidence sections | Detection is ledger-native too (datu watch) |
| PRIV-INC-02 | Breach Classification | pass | P1-P4 severity table with response times | Severity defined by data type and blast radius |
| PRIV-INC-03 | Regulatory Notification | pass | Regulator matrix naming NPC (72 h) and the EU lead authority, with templates | The controller notifies; the software provides the evidence trail |
| PRIV-INC-04 | Data Subject Notification | pass | Art. 34 templates plus datu watch telling the affected key | Two channels: operator prose and ledger-native notice |
| PRIV-VEN-01 | Vendor Due Diligence | not-applicable | No vendors process personal data for the project; dependencies are inventoried by SBOM and audited | Operators assess their own vendors |
| PRIV-VEN-02 | Processor Agreements | not-applicable | The project is not a processor and engages none; operator DPAs live in the operator ROPA | Nothing to sign at the software level |
| PRIV-VEN-03 | Ongoing Monitoring | not-applicable | No vendor relationships; supply chain covered by SBOM, advisory gates, signed releases | N/A for the software |
| PRIV-XBT-01 | Transfer Assessment | pass | PRIVACY.md global-ledger statement; cross-border position per activity in legal-bases.json | The artifact is global by design; the notice says so |
| PRIV-XBT-02 | Adequacy Assessment | not-applicable | The project transfers nothing; operators assess adequacy for their publishing | N/A for the software |
| PRIV-XBT-03 | Standard Contractual Clauses | not-applicable | SCCs are contracts between controllers and processors; the software signs none | N/A for the software |
| PRIV-XBT-04 | Data Localization Requirements | not-applicable | The software imposes no localization; localization regimes are an operator assessment | N/A for the software |
| PRIV-RET-01 | Retention Schedule | pass | retention-policy.md append-only section; retention per activity in legal-bases.json | Schedules per activity; the ledger's is 'while mirrors hold it' |
| PRIV-RET-02 | Secure Disposal | pass | No deletion primitive by design: revocation for statements, key destruction for sealed fields, operator-side disposal documented | Caveat: disposal is cryptographic or social, never a silent delete |
| PRIV-RET-03 | Data Minimization | pass | Keys-only identifiers, sealing before publishing, first_seen never synced or served | Minimisation is structural |
| PRIV-TRN-01 | Employee Privacy Training | not-applicable | No employees; the manuals are the material for operators | N/A for the software project |
| PRIV-TRN-02 | Specialized Role Training | not-applicable | Operator roles are covered by runbooks and manuals | N/A for the software project |
| PRIV-TRN-03 | Privacy Awareness Program | not-applicable | No staff to run awareness for; the notice and manuals are public | N/A for the software project |

## Summary

29 attested pass, 11 not applicable, 0 unaddressed.

The N/A groups are organisational by nature: a DPO, staff training, vendor
DPAs and SCCs exist for organisations with staff and vendors. The software
ships the mechanisms (consent ceremonies, registers, notice, revocation,
watch) and each operator completes its own side.
