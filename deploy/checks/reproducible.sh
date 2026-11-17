#!/usr/bin/env bash
# Bit-reproducible release builds (readiness item O2): identical inputs
# must produce byte-identical binaries, or nobody can verify that what
# they downloaded is what CI built from the tag. Two builds run from two
# different checkout paths (path length differences are exactly what
# leaks into binaries without remapping); both remap the workspace and
# the cargo registry to fixed prefixes and pin SOURCE_DATE_EPOCH, which
# is the same recipe the release workflow uses.
#
# Tests HEAD as committed (git archive), so uncommitted work is ignored.
set -euo pipefail
cd "$(dirname "$0")/../.."

EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}
Work=$(mktemp -d /tmp/datu-repro.XXXXXX)
trap 'rm -rf "$Work"' EXIT

for round in a b; do
  mkdir "$Work/$round"
  git archive HEAD | tar -x -C "$Work/$round"
  echo "build round $round (checkout $Work/$round)"
  (cd "$Work/$round" && \
    SOURCE_DATE_EPOCH="$EPOCH" \
    RUSTFLAGS="--remap-path-prefix=$Work/$round=/usr/src/datu --remap-path-prefix=$HOME/.cargo/registry=/usr/src/cargo" \
    cargo build --release --locked -p datu-cli -p datu-indexer)
done

fail=0
for bin in datu datu-indexer; do
  a=$(shasum -a 256 "$Work/a/target/release/$bin" | awk '{print $1}')
  b=$(shasum -a 256 "$Work/b/target/release/$bin" | awk '{print $1}')
  if [ "$a" = "$b" ]; then
    echo "PASS: $bin reproducible ($a)"
  else
    echo "FAIL: $bin differs between checkouts:"
    echo "  $a  (a)"
    echo "  $b  (b)"
    fail=1
  fi
done
exit $fail
