# Incident Response Plan - DATU Ledger

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| P1 - Critical | Active data breach, system compromise | 15 minutes |
| P2 - High | Vulnerability being exploited, data at risk | 1 hour |
| P3 - Medium | Vulnerability identified, no active exploit | 4 hours |
| P4 - Low | Security improvement needed | 24 hours |

## Response Process

### 1. Detection and Reporting
- Automated monitoring alerts
- Team member reports
- External vulnerability reports

### 2. Assessment
- Determine severity level
- Identify affected systems and data
- Assess impact on personal data

### 3. Containment
- Isolate affected systems
- Preserve evidence
- Prevent further data loss

### 4. Eradication
- Remove threat
- Patch vulnerabilities
- Rotate compromised credentials

### 5. Recovery
- Restore from clean backups
- Verify system integrity
- Resume normal operations

### 6. Post-Incident
- Document lessons learned
- Update security controls
- Review and update incident response plan

## Regulator matrix (know yours before you need it)

| Jurisdiction | Authority | Deadline | Trigger |
|---|---|---|---|
| Philippines (DPA 2012, IRR) | National Privacy Commission (NPC) | 72 hours from knowledge | Breach involving sensitive personal information, or likely to give rise to identity fraud or harm |
| EU/EEA (GDPR Art. 33) | Lead supervisory authority | 72 hours from awareness | Breach likely to result in a risk to rights and freedoms |
| Data subjects (Art. 34 / DPA Sec. 20(f)) | the affected people | without undue delay | High risk to rights and freedoms |

The software's part in this: `datu watch` notifies the affected key when a
statement about it is revoked, so the people a breach touches can be told
over the same channel that holds their record.

## GDPR Breach Notification

- **72 hours**: Notify supervisory authority (Article 33)
- **Without undue delay**: Notify affected data subjects if high risk (Article 34)

## Contacts

| Role | Contact |
|------|---------|
| Incident Lead | [To be completed] |
| DPO | [To be completed] |
| Legal | [To be completed] |
| Supervisory Authority | [To be completed] |
