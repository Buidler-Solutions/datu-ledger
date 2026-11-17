# Key custody (readiness item S7)

Who may hold which key, how keys are made, backed up, and rotated. The
rotation procedure below is exactly what `deploy/drills/key-rotation.sh`
proves; run the drill before trusting the procedure.

## The keys that exist

| Key | File | What it can do | Blast radius if leaked |
|---|---|---|---|
| Node identity (Ed25519) | `<data-dir>/secret.key` | Sign entries, checkpoints, attestations as this identity | Attacker authors entries in your name; gated nodes drop the key once revoked |
| Node post-quantum (ML-DSA-65) | `<data-dir>/secret.mldsa65` | Sign entries/checkpoints with PQ signature | Same as above |
| Signet vault identity | vault data dir (see `datu signet`) | Sign as the vault identity, unseal sealed records | Custody of every record sealed to it; see bridge-hardening.md for the rate and lockout layers in front of it |
| Genesis founder keys | `~/.datu-genesis/` | Sign future founder acts (genesis v3, founder statements) | Anyone can sign as the founder; special case, see docs/genesis-backup.md |

Custody rules:
- One key per host. Never copy `secret.key`/`secret.mldsa65` between
  machines; clone history instead (`bundle export` + `bundle import`
  under a freshly `init`-ed identity, which is the rotation path below).
- Backups are encrypted archives of the data dir, made on the key's own
  host, stored off-host. Never move a plaintext key file anywhere.
- Attested writers and trust roots (attestors) are held to the strictest
  standard: their compromise flips a gate for every validator that pins
  them, so their data dirs live on the most locked-down hosts in the
  cell (see topology.md).
- The genesis founder keys follow their own procedure:
  docs/genesis-backup.md. The ledger does not need them to run; losing
  them closes a one-way door, leaking them is worse than losing them.

## Key ceremony (new identity that will matter)

1. Prepare a dedicated, offline-capable host: fresh OS, full-disk
   encryption, no agents. Nothing joins it to a network yet.
2. `datu --data-dir <dir> init`, then `datu --data-dir <dir> keys` to
   record the identity (Ed25519 hex) in the custody log.
3. Back up the whole data dir as one encrypted archive:

   ```bash
   tar -C $(dirname <dir>) -cf - $(basename <dir>) | \
     openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -out node-backup.enc
   ```

   The passphrase is typed by the custodian, on the key's own host; it
   must not pass through any tool, script or assistant.
4. Verify the backup restores (empty host: decrypt, extract, `datu
   --data-dir <dir> verify`), then store it off-host (two locations, two
   people for trust-root keys).
5. Only then attach the host to the network and attest the key.

## Rotation procedure (compromise or scheduled)

The invariant: history is data, identity is a key. Rotation moves to a
new key while history survives, and the old key stops mattering.

1. **Recover history on a new host/key**: on the old (or compromised)
   host, `datu bundle export --out w.bundle` if still possible; on the
   new host, `datu init` (fresh key) and `datu bundle import --input
   w.bundle`. The new host verifies every entry; entry counts must match.
   If the old host is gone, sync the new host from peers instead - the
   ledger lives on every node, not in your key.
2. **Revoke the old key**: a trust root of the gated namespaces runs
   `datu attest revoke --key <old-key-hex> --reason "..."`. This is a new
   ledger entry, not an edit; validators that pin the trust root refuse
   the old key's writes from the moment they sync the revocation. The
   refusal is visible in sync output as
   `skipped by this node's policy - ... revoked by a configured trust root`.
3. **Attest the new key**: `datu attest create --subject <new-key-hex>
   --claims '{"role":"writer","replaces":"<old-key-hex>"}'` so the
   custody trail on the ledger links old to new.
4. **Flip the local policy too** if the old key was listed explicitly in
   any validator's `policy.json` (`writers`/`attestors`): edit and
   restart, then confirm the new key's entries sync in.
5. **Freeze, never delete** the old data dir: entries signed by the old
   key remain valid history. Revocation gates admission; it does not
   rewrite the past. If the attacker also published entries, keep them
   and the dispute records - that is the accountability trail (see
   incident-runbooks.md).

## The drill

```bash
./deploy/drills/key-rotation.sh          # PORT=7600 to move it
```

Casts writer W (leaks), trust root T, validator V; proves: history
survives a host+key move via bundle import, T's `attest revoke` makes V
refuse the leaked key (`revoked by a configured trust root` in sync
output), and T's re-attestation admits the new key's writes. PASS lines
at the end mean the ceremony works with this code; run it after any
change to policy, attest or sync code.
