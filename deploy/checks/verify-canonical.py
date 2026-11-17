#!/usr/bin/env python3
"""Verify the canonical fixture with the pure-Python RP verifier.

Checks the Ed25519 signatures over the pinned bytes and rebuilds the
SignetAuth byte string independently, so a canonicalization drift on the
Rust side fails here even though the JS and Python code never see borsh.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "rp-verifier-python"))
from datu_rp_verify import verify_ed25519  # noqa: E402

fixture = json.loads(
    (ROOT / "crates/core/tests/fixtures/canonical_vectors.json").read_text(encoding="utf-8")
)

def check(name, canonical_hex, sig_hex):
    if not verify_ed25519(fixture["public_key_hex"], bytes.fromhex(canonical_hex), sig_hex):
        raise SystemExit(f"{name}: signature does not verify")
    print(f"ok: {name} signature over pinned bytes")

check("entry", fixture["entry"]["canonical_hex"], fixture["entry"]["signature_hex"])
check("auth", fixture["auth"]["canonical_hex"], fixture["auth"]["signature_hex"])
check("checkpoint", fixture["checkpoint"]["canonical_hex"], fixture["checkpoint"]["signature_hex"])

auth = fixture["auth"]
rebuilt = "datu-auth-v1\n{rp_id}\n{origin}\n{nonce_hex}\n{expires_at_ms}\n".format(
    rp_id=auth["rp_id"], origin=auth["origin"], nonce_hex=auth["nonce_hex"],
    expires_at_ms=auth["expires_at_ms"],
)
if rebuilt.encode().hex() != auth["canonical_hex"]:
    raise SystemExit("auth canonical bytes differ from the Python rebuild")
print("ok: auth canonical bytes match the Python rebuild")
print("PASS: Python verified canonical signatures")
