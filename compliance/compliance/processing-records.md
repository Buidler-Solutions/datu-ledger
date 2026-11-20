# Records of Processing Activities - DATU Ledger

## Article 30 Requirements

### Controller Information

- **Organization**: [To be completed]
- **Contact**: [To be completed]
- **DPO**: [To be completed]

### Processing Activities

| Activity | Purpose | Data Categories | Recipients | Retention | Transfers | Security Measures |
|----------|---------|----------------|------------|-----------|-----------|-------------------|
| | | | | | | |

## Documentation

Each processing activity must document:
1. Purpose of processing
2. Legal basis
3. Categories of data subjects
4. Categories of personal data
5. Categories of recipients
6. International transfers
7. Retention periods
8. Technical and organisational security measures

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
