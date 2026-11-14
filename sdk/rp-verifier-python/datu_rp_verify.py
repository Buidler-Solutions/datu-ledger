#!/usr/bin/env python3
"""SignetAuth relying-party verifier for DATU (datu-auth-v1).

Verifies a SignetAuth login assertion returned by a Signet bridge
(`POST /v1/wallet/auth-assert`, or the panel's signIn) exactly the way
`datu signet auth-verify` and the browser SDK do:

- recompute the canonical signed bytes
      datu-auth-v1\\n<rp_id>\\n<origin>\\n<nonce_hex>\\n<expires_at_ms>\\n
- check the assertion matches the challenge this app issued
- check the challenge is still live
- verify the Ed25519 signature against the identity's public key

Standard library only: if the `cryptography` package is installed it is
used for the Ed25519 math, otherwise a compact RFC 8032 implementation
runs (fast enough for logins).

Library use:

    from datu_rp_verify import new_challenge, verify_assertion
    challenge = new_challenge(rp_id="app.example.com", origin="https://app.example.com")
    # ... send the challenge to the wallet, get `assertion` back ...
    result = verify_assertion(assertion, challenge)
    if not result["ok"]:
        raise PermissionError(result["reason"])

Command line:

    python3 datu_rp_verify.py --assertion assertion.json \\
        --rp-id app.example.com --origin https://app.example.com

    exit 0: valid and live; exit 1: rejected (reason on stdout).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time

AUTH_DOMAIN = "datu-auth-v1"
NONCE_BYTES = 16
DEFAULT_TTL_MS = 60_000

# ---------------------------------------------------------------- ed25519 ---

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)  # extended coordinates (X, Y, Z, T)
_IDENT = (0, 1, 1, 0)


def _point_add(P, Q):
    a = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    b = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    c = 2 * P[3] * Q[3] * _D % _P
    d = 2 * P[2] * Q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, P):
    q_pt = _IDENT
    while s > 0:
        if s & 1:
            q_pt = _point_add(q_pt, P)
        P = _point_add(P, P)
        s >>= 1
    return q_pt


def _point_equal(P, Q) -> bool:
    # x1/z1 == x2/z2 and y1/z1 == y2/z2
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _P != 0:
        return False
    return True


def _point_compress(P) -> bytes:
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % _P
    y = P[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % _Q


def _ed25519_pure_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a_pt = _point_decompress(public)
    r_pt = _point_decompress(signature[:32])
    if a_pt is None or r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = _sha512_modq(signature[:32] + public + msg)
    return _point_equal(_point_mul(s, _G), _point_add(r_pt, _point_mul(h, a_pt)))


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    """Public key of a 32-byte seed (test helper; RPs never hold secrets)."""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))


def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    """Sign with a 32-byte seed (test helper only)."""
    a, prefix = _secret_expand(secret)
    a_bytes = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    r_bytes = _point_compress(_point_mul(r, _G))
    h = _sha512_modq(r_bytes + a_bytes + msg)
    s = (r + h * a) % _Q
    return r_bytes + int.to_bytes(s, 32, "little")


def verify_ed25519(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    """True when the Ed25519 signature over message verifies for pubkey."""
    public = bytes.fromhex(pubkey_hex)
    signature = bytes.fromhex(signature_hex)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _ed25519_pure_verify(public, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except Exception:
        return False


# ------------------------------------------------------------ signetauth ---


def canonical_bytes(rp_id: str, origin: str, nonce: str, expires_at_ms: int) -> bytes:
    """The exact byte string the wallet signs (crates/core/src/auth.rs)."""
    return f"{AUTH_DOMAIN}\n{rp_id}\n{origin}\n{nonce}\n{expires_at_ms}\n".encode()


def new_challenge(rp_id: str, origin: str, ttl_ms: int = DEFAULT_TTL_MS,
                  nonce: str | None = None, now_ms: int | None = None) -> dict:
    if not rp_id:
        raise ValueError("rp_id is required")
    if not origin:
        raise ValueError("origin is required")
    if nonce is None:
        nonce = secrets.token_hex(NONCE_BYTES)
    now = now_ms if now_ms is not None else _now_ms()
    return {
        "rp_id": rp_id,
        "origin": origin,
        "nonce": nonce,
        "expires_at_ms": now + ttl_ms,
    }


def _now_ms() -> int:
    return int(time.time() * 1000)


def verify_assertion(assertion: dict, challenge: dict,
                     now_ms: int | None = None,
                     expected_pubkey: str | None = None) -> dict:
    """Verify an assertion against the challenge this app issued.

    Returns {"ok": bool, "reason": str}; on success "pubkey" carries the
    identity key so the RP can bind it to an account. Pass expected_pubkey
    (the key you have on file for that account) to reject assertions signed
    by any other identity. Nonce single-use tracking stays the RP's job
    (keep a spent-nonce set per challenge).
    """
    if not isinstance(assertion, dict):
        return {"ok": False, "reason": "no assertion returned"}
    if assertion.get("domain", AUTH_DOMAIN) != AUTH_DOMAIN:
        return {"ok": False, "reason": f"unexpected domain {assertion.get('domain')}"}
    for field in ("rp_id", "origin", "nonce", "expires_at_ms"):
        if assertion.get(field) != challenge.get(field):
            return {"ok": False,
                    "reason": "assertion does not match the challenge this app issued"}
    now = now_ms if now_ms is not None else _now_ms()
    if now >= challenge["expires_at_ms"]:
        return {"ok": False, "reason": "challenge expired"}
    pubkey = assertion.get("pubkey")
    signature = assertion.get("signature")
    if not pubkey or not signature:
        return {"ok": False, "reason": "assertion is missing pubkey or signature"}
    if expected_pubkey is not None and pubkey != expected_pubkey:
        return {"ok": False, "reason": "pubkey does not match the expected identity"}
    message = canonical_bytes(
        assertion["rp_id"], assertion["origin"],
        assertion["nonce"], assertion["expires_at_ms"],
    )
    if not verify_ed25519(pubkey, message, signature):
        return {"ok": False, "reason": "signature invalid"}
    return {"ok": True, "reason": "valid and live", "pubkey": pubkey}


# -------------------------------------------------------------------- cli ---


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a SignetAuth (datu-auth-v1) login assertion")
    parser.add_argument("--assertion", required=True,
                        help="path to the assertion JSON the wallet returned")
    parser.add_argument("--rp-id", required=True, help="the rp_id you issued")
    parser.add_argument("--origin", required=True, help="the origin you issued")
    parser.add_argument("--nonce", help="nonce you issued (default: taken from the assertion)")
    args = parser.parse_args(argv)

    with open(args.assertion, "r", encoding="utf-8") as handle:
        assertion = json.load(handle)
    challenge = {
        "rp_id": args.rp_id,
        "origin": args.origin,
        "nonce": args.nonce if args.nonce is not None else assertion.get("nonce"),
        "expires_at_ms": assertion.get("expires_at_ms"),
    }
    result = verify_assertion(assertion, challenge)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
