# Incident runbooks (readiness item O5)

Four production incidents, each with detection, containment, recovery and
the evidence to keep. "Owner" is the role that runs the steps; in a small
deployment one person holds several roles. All commands assume the
affected node's data dir via `--data-dir`.

## 1. Key compromise (a node's or an identity's secret key leaked)

Owner: operator + key custodian. Severity: high.

Detect: key material seen outside its host (leaked backup, malware, stolen
laptop), or entries you did not author appearing in your feed.

Contain:
1. Stop the node (`datu node` process) so no further writes use the key.
2. Revoke trust in the key: every attestor of that key publishes
   `datu attest revoke --key <key-hex>` (a new `identity.revoke` entry,
   never an edit). Gated nodes stop admitting the key from that moment.
3. If the compromised key was a policy writer or attestor, edit
   `policy.json` (remove from `writers`/`attestors`) and restart affected
   validators.

Recover:
4. `datu init` a fresh data dir (new keys), sync history from peers
   (`datu sync --peer ...`), then re-attest the new key
   (`datu attest create --subject <new-key>`).
5. Feed continuity: the new key starts a new feed. If authorship linkage
   matters, publish one entry on the old feed pointing at the new key
   BEFORE revocation completes, or reference the old feed's head from the
   new feed's first entry (`publish --ref <old-head-id>`).

Evidence to keep: the revoke entries, the old data dir (frozen copy), the
leak report. Note: entries signed by the stolen key REMAIN valid history -
revocation gates admission, it does not rewrite the past. If the attacker
forked the feed, run the fork runbook below; the dispute and the revoke
entries together are the accountability trail.

## 2. Disk full

Owner: operator. Severity: medium (writes stall; reads and verification
keep working).

Detect: disk alerts at 70/85% (see disk-growth-and-retention.md); SQLite
write errors (`database or disk is full`) in the node log.

Contain:
1. Free scratch space on the volume (logs, cores, temp) - never ledger
   files.
2. If the store itself is the constraint, stand up a scoped node for what
   matters next (`--namespace`-scoped store) while the full node stays
   read-only.

Recover:
3. Move or enlarge the volume, or migrate: `datu bundle export` on the old
   volume, `datu init` + `datu bundle import` on the new one (the
   backup-restore drill is this exact path), then resync from peers.
4. Compaction: a bundle import into a fresh dir drops SQLite freelist
   bloat; check `du` before/after.

Prevent: retention rules for projections only (never ledger), monitoring
per the sizing model.

## 3. Split brain / fork (two incompatible histories circulate)

Owner: operator of each affected node. Severity: high.

Detect: syncs fail closed with "contradicting" / "peer checkpoint
contradicts" messages; `datu disputes` shows recorded conflicts.

Contain:
1. Do NOT delete either side. Both chains are evidence.
2. Collect witness streams: `datu witness export --out <signer>.stream`
   from witnesses that observed each side.
3. Prove it: `datu prove-fork --a w1.stream --b w2.stream --out
   evidence.json` (verdict `FORK_PROVEN`, exit 2) or against a bundle:
   `datu bundle export` on one side, `datu prove-fork --against` on the
   other. Ship the evidence package to the governance forum.

Recover:
4. Adjudication is governance, not code: the mesh decides which history is
   official (checkpoint coverage by trusted witnesses is the tiebreaker).
   Nodes keep both chains locally; gated namespaces follow the policy
   chain's verdict.
5. The disputing author publishes a signed resolution entry referencing
   the dispute; `datu disputes` surfaces it alongside the conflict.

## 4. Doxxed record (personal data landed where it should not have)

Owner: operator + data protection owner. Severity: high (legal exposure).

Detect: report or audit finds plaintext personal data in a public
namespace (policy `require_sealed` should have prevented it; a rule gap or
a mis-scoped node let it through).

Contain:
1. The entry CANNOT be deleted or edited - it is evidence. Do not attempt
   store surgery; a tampered store fails verification everywhere.
2. If the data was in a sealed field, stop any pending release of the
   field key: the crypto-shredding path is to never publish the release
   (un-released sealed fields stay ciphertext forever, everywhere).
3. Rotate what the leak enables: if the plaintext contained credentials
   or key material, rotate those independently of the ledger.

Recover:
4. Publish a signed correction/revocation entry in the same namespace
   marking the record superseded (`publish --ref <entry-id>` with a
   correction payload).
5. Close the hole that let it in: add the field to `require_sealed` in the
   namespace rule, or fix the node scoping, and confirm a re-attempt is
   denied (`datu policy show`, then test-publish).
6. Legal notification per jurisdiction (GDPR breach rules may apply) - the
   append-only trail of correction + policy change is the remediation
   record auditors will ask for.

## Cross-incident rules

- Never edit `node.db` by hand; never delete entries; every remedy is a
  new signed entry or a policy change.
- Frozen copies (data dir copied with the node stopped) are the evidence
  format; bundles are the transport format.
- After any incident: rerun `datu verify` on affected nodes, log the
  timeline in the operations journal, and add a drill if the incident
  exposed an untested path (deploy/drills/).
