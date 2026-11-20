# Consent management

GDPR-ART5-001 asks for a consent mechanism where consent is the basis, a
record of legal bases, and a clear privacy notice. DATU answers all three
with the protocol itself rather than a bolted-on banner.

## How consent is captured

Consent in DATU is a **signature on a specific document**, bound to a role
and a key. There is no checkbox that can drift away from what was agreed:

| Act | Who signs | Record |
|---|---|---|
| Being attested by a registry | the citizen, with the key being enrolled (`subject` role) | `identity.enroll` entry holding both signatures |
| Replacing a lost key | the citizen (new key, `citizen` role) and each guardian (`guardian` role) | `identity.recover` entry |
| Being a party to a record | every affected party, each under its own role | the party-signed document the operator publishes |
| Signing in to a site | the wallet, after the review screen shows rp_id and origin | an assertion, single-use; nothing on the ledger |

Key property: the enrollment and recovery signature **only verifies against
the key being enrolled or replaced**. A registry cannot consent on someone's
behalf, and a document edited after signing fails verification (`datu
enroll approve` refuses, and so does the consent register).

## How the record is read back

```bash
# every statement this key signed, oldest first
datu consent --subject <pubkey-hex> --json

# the vouching side: who attests this key, with what claims
datu attest status --subject <pubkey-hex>
```

`datu consent` reads the entries the node holds, verifies each signature
again, and prints the kind, the role, who published it, the summary and the
entry id. Unverifiable documents never appear (see the unit tests in
`crates/core/src/consent.rs`).

## How consent is withdrawn

Withdrawal is a statement, not a deletion, because the ledger is append-only
and mirrored:

1. A trust root publishes `identity.revoke` naming the attestation (or the
   key, for direct ejection). Every verifier honours it; `datu watch`
   reports it to the affected key.
2. A guardian recovery (`datu enroll recover`) replaces a key outright and
   revokes the lost one in the same act.
3. Going forward, the operator stops publishing personal payloads and seals
   the fields it must keep.

Where a copy already exists on independent mirrors, the operator documents
the residual copies in its records of processing (Art. 17(2) effort note).
That limitation is inherent to any mirrored accountability ledger and is
disclosed in the privacy notice rather than hidden.

## Legal bases and notices

- Register: [`compliance/legal-bases.json`](legal-bases.json), one entry per
  processing activity, with the GDPR article, the DPA 2012 counterpart,
  evidence pointers and retention.
- Notice: [`PRIVACY.md`](../PRIVACY.md) at the repository root, linked from
  the README.
- Per-deployment: the operator confirms or amends both in its own copy; the
  software cannot choose a basis for the operator.

## Evidence in the compliance record

The governance record `gov-1795171328891-1` carries this document, the
privacy notice, the legal-basis register and the ceremony drills as evidence
references, so the provenance chain shows the basis of the claim rather than
the claim alone.
