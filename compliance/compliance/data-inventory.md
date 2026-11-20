# Data Inventory - DATU Ledger

## Data Categories

| Category | Type | Classification | Retention | Legal Basis |
|----------|------|---------------|-----------|-------------|
| User profiles | Personal | Restricted | Account lifetime + 30 days | Contract |
| Email addresses | Personal | Confidential | Account lifetime + 30 days | Contract |
| Authentication data | Personal | Restricted | Session duration | Contract |
| Audit logs | Operational | Internal | 1 year | Legal obligation |

## Data Flows

Document all data flows including:
- Data collection points
- Processing activities
- Data storage locations
- Third-party data sharing
- Cross-border transfers

## Third-Party Processors

| Processor | Purpose | Data Shared | DPA Signed | Location |
|-----------|---------|-------------|------------|----------|
| | | | | |

---

## DATU specifics (this section governs for the ledger itself)

| Category | Classification | Where it lives | Lawful basis |
|----------|----------------|----------------|--------------|
| Ed25519 / ML-DSA-65 public keys | Pseudonymous identifier | Public ledger (identity statements) | Consent / legitimate interest of the registry |
| Attestation claims (legal name, role, label) | Personal | Public ledger, sealed where the operator chooses | Registry's performance of a public task or consent |
| Enrollment / recovery ceremony records | Personal metadata | Public ledger (party-signed documents) | Consent (both signatures are the consent) |
| Published payloads | Depends on the operator | Public ledger | Operator's lawful basis, documented per deployment |
| Sealed documents | Restricted | Operator database only, never the ledger | Operator's lawful basis |
| IP addresses in HTTP logs | Personal | Transient, operator-side | Security (legitimate interest) |

No KYC data, accounts, or marketing categories exist in this system. The
generic rows above are the template default and do not describe DATU.
