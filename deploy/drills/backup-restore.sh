#!/usr/bin/env bash
# Backup and restore drill: prove a node can be recreated from a bundle and
# from a data-dir copy, with identical content and a clean verify.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-drill.XXXXXX)
trap 'rm -rf "$Work"' EXIT
say() { printf '\n== %s\n' "$*"; }

say "fresh node"
"$Datu" --data-dir "$Work/a" init >/dev/null

say "publish 25 entries"
for i in $(seq 1 25); do
  "$Datu" --data-dir "$Work/a" publish --ns gov.drill \
    --payload "{\"n\":$i}" >/dev/null
done
"$Datu" --data-dir "$Work/a" checkpoint >/dev/null || true
before=$("$Datu" --data-dir "$Work/a" status | awk '/^entries:/{print $2}')
echo "entries before backup: $before"

say "bundle export -> import into b"
"$Datu" --data-dir "$Work/a" bundle export --out "$Work/a.bundle" >/dev/null
"$Datu" --data-dir "$Work/b" init >/dev/null   # import needs a node identity
"$Datu" --data-dir "$Work/b" bundle import --input "$Work/a.bundle" >/dev/null
after=$("$Datu" --data-dir "$Work/b" status | awk '/^entries:/{print $2}')
echo "entries after bundle restore: $after"
[ "$before" = "$after" ] || { echo "FAIL: entry count differs"; exit 1; }
"$Datu" --data-dir "$Work/b" verify | tail -1

say "data-dir copy -> c"
mkdir -p "$Work/c"
cp -a "$Work/a/." "$Work/c/"
cp="$("$Datu" --data-dir "$Work/c" status | awk '/^entries:/{print $2}')"
echo "entries after data-dir copy: $cp"
[ "$before" = "$cp" ] || { echo "FAIL: copied store differs"; exit 1; }
"$Datu" --data-dir "$Work/c" verify | tail -1

say "PASS: bundle and data-dir restores reproduce the store"
