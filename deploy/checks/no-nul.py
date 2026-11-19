#!/usr/bin/env python3
"""Fail if any Rust source contains a NUL byte.

A literal NUL in a .rs file makes rg/grep treat the file as binary, breaks
diff review, and once cost us a test: the wasm magic in the contract test
must be written with escapes (b"\x00asm..."), not raw bytes. This runs in
CI so a tool writing raw bytes gets caught immediately.
"""
import pathlib
import sys

bad = []
for path in pathlib.Path("crates").rglob("*.rs"):
    if b"\x00" in path.read_bytes():
        bad.append(str(path))

if bad:
    print("NUL bytes found in:", *bad, sep="\n  ")
    sys.exit(1)
print("sources are text: no NUL bytes in crates/**/*.rs")
