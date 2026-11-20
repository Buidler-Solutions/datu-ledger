# Contributing

Thanks for helping build an accountability ledger. The rules are short and
the gates are strict, because trust is the product.

## Before you start

- Read `PRIVACY.md` and `compliance/consent-management.md`: this project
  processes personal statements, and contributions must keep that honest.
- For anything security-sensitive, read `SECURITY.md` first.

## The gates (all must pass locally)

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # always with -D
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
node .dev-logs/tools/explorer-strand-test.mjs 2>/dev/null || true
cd apps/wallet && flutter analyze && flutter test      # wallet changes
python3 deploy/checks/compose-hardening.py
python3 deploy/checks/legal-bases.py
python3 deploy/checks/spdx.py
```

CI runs the same set plus the drills in `deploy/drills/` and six security
gates. A pull request that reddens a gate will not merge.

## Style

- Commit messages: `scope: what changed` (for example `cli: ...`, `store: ...`,
  `wallet: ...`, `docs: ...`), body explains why.
- Tests come with the change; new behaviour without a test is incomplete.
- No secrets, no personal data in fixtures, no em dashes in docs.
- New namespaces or processing activities need an entry in
  `compliance/legal-bases.json` (the gate will tell you).

## Recipes

- New CLI command: add the subcommand in `crates/cli/src/main.rs`, keep logic
  in tests, document it in the README and, if it touches personal data, in
  `compliance/`.
- New namespace: register it in the legal-basis register, gate it in writer
  policy if it carries authority, and add a drill.
- New deployment file: it must pass `deploy/checks/compose-hardening.py`
  (non-root user, read-only rootfs, cap_drop ALL, no-new-privileges, limits,
  digest-pinned images).
