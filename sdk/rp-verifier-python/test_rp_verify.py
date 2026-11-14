"""SignetAuth RP verifier tests.

Runs with the stdlib alone: python3 -m unittest discover -s sdk/rp-verifier-python

The fixture assertion was produced by a real Signet bridge (datu 0.2.0,
crates/core auth.rs) for the spec's worked example, so these tests pin the
canonical byte string across Rust, JS and Python.
"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datu_rp_verify import (  # noqa: E402
    AUTH_DOMAIN,
    canonical_bytes,
    ed25519_public_key,
    ed25519_sign,
    new_challenge,
    verify_assertion,
    verify_ed25519,
)

HERE = os.path.dirname(os.path.abspath(__file__))

# RFC 8032 test vectors (empty message and the two-byte 0xaf82 message).
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        bytes.fromhex("af82") * 0,  # empty
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        bytes.fromhex("af82"),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for secret_hex, public_hex, msg, sig_hex in RFC8032:
            secret = bytes.fromhex(secret_hex)
            self.assertEqual(ed25519_public_key(secret).hex(), public_hex)
            self.assertEqual(ed25519_sign(secret, msg).hex(), sig_hex)
            self.assertTrue(verify_ed25519(public_hex, msg, sig_hex))

    def test_rejects_bad_signature(self):
        _, public_hex, msg, sig_hex = RFC8032[0]
        bad = bytearray(bytes.fromhex(sig_hex))
        bad[0] ^= 1
        self.assertFalse(verify_ed25519(public_hex, msg, bad.hex()))

    def test_rejects_wrong_key(self):
        _, _, msg, sig_hex = RFC8032[0]
        self.assertFalse(verify_ed25519(RFC8032[1][1], msg, sig_hex))


class CanonicalBytesTests(unittest.TestCase):
    def test_matches_the_spec_worked_example(self):
        got = canonical_bytes(
            "app.example.com", "https://app.example.com",
            "ab" * 16, 4102444800000,
        )
        want = (
            "datu-auth-v1\napp.example.com\nhttps://app.example.com\n"
            "abababababababababababababababab\n4102444800000\n"
        ).encode()
        self.assertEqual(got, want)


def signed_assertion(secret, challenge):
    """Build a wallet-shaped assertion for a challenge, like auth-assert does."""
    message = canonical_bytes(
        challenge["rp_id"], challenge["origin"],
        challenge["nonce"], challenge["expires_at_ms"],
    )
    return {
        "domain": AUTH_DOMAIN,
        **challenge,
        "pubkey": ed25519_public_key(secret).hex(),
        "signature": ed25519_sign(secret, message).hex(),
    }


class VerifyAssertionTests(unittest.TestCase):
    SECRET = bytes.fromhex(RFC8032[0][0])
    NOW = 4_000_000_000_000

    def test_valid_assertion_passes(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(self.SECRET, challenge)
        result = verify_assertion(assertion, challenge, now_ms=self.NOW + 1_000)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pubkey"], RFC8032[0][1])

    def test_expired_challenge_rejected(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(self.SECRET, challenge)
        result = verify_assertion(assertion, challenge, now_ms=challenge["expires_at_ms"] + 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "challenge expired")

    def test_challenge_mismatch_rejected(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(self.SECRET, challenge)
        other = dict(challenge, nonce="ef" * 16)
        result = verify_assertion(assertion, other, now_ms=self.NOW)
        self.assertFalse(result["ok"])
        self.assertIn("match", result["reason"])

    def test_tampered_signature_rejected(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(self.SECRET, challenge)
        first = int(assertion["signature"][:2], 16) ^ 1
        assertion["signature"] = format(first, "02x") + assertion["signature"][2:]
        result = verify_assertion(assertion, challenge, now_ms=self.NOW)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "signature invalid")

    def test_unexpected_identity_rejected(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(bytes.fromhex(RFC8032[1][0]), challenge)
        result = verify_assertion(assertion, challenge, now_ms=self.NOW,
                                  expected_pubkey=RFC8032[0][1])
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "pubkey does not match the expected identity")

    def test_wrong_domain_rejected(self):
        challenge = new_challenge("app.example.com", "https://app.example.com",
                                  nonce="cd" * 16, ttl_ms=60_000, now_ms=self.NOW)
        assertion = signed_assertion(self.SECRET, challenge)
        assertion["domain"] = "datu-auth-v0"
        result = verify_assertion(assertion, challenge, now_ms=self.NOW)
        self.assertFalse(result["ok"])


class RealBridgeFixtureTests(unittest.TestCase):
    """Cross-language pin: an assertion minted by the Rust bridge verifies."""

    def setUp(self):
        with open(os.path.join(HERE, "test_fixture_assertion.json"), encoding="utf-8") as fh:
            self.assertion = json.load(fh)
        self.challenge = {
            "rp_id": self.assertion["rp_id"],
            "origin": self.assertion["origin"],
            "nonce": self.assertion["nonce"],
            "expires_at_ms": self.assertion["expires_at_ms"],
        }

    def test_signature_verifies_against_identity_key(self):
        message = canonical_bytes(
            self.challenge["rp_id"], self.challenge["origin"],
            self.challenge["nonce"], self.challenge["expires_at_ms"],
        )
        self.assertTrue(
            verify_ed25519(self.assertion["pubkey"], message, self.assertion["signature"]))

    def test_full_verdict_while_live(self):
        now = 4_102_444_799_999  # one millisecond before the fixture expiry
        result = verify_assertion(self.assertion, self.challenge, now_ms=now)
        self.assertTrue(result["ok"], result)


class CliTests(unittest.TestCase):
    def test_cli_accepts_fixture(self):
        fixture = os.path.join(HERE, "test_fixture_assertion.json")
        script = os.path.join(HERE, "datu_rp_verify.py")
        done = subprocess.run(
            [sys.executable, script, "--assertion", fixture,
             "--rp-id", "app.example.com", "--origin", "https://app.example.com"],
            capture_output=True, text=True,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        verdict = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertTrue(verdict["ok"])

    def test_cli_rejects_wrong_rp(self):
        fixture = os.path.join(HERE, "test_fixture_assertion.json")
        script = os.path.join(HERE, "datu_rp_verify.py")
        done = subprocess.run(
            [sys.executable, script, "--assertion", fixture,
             "--rp-id", "evil.example", "--origin", "https://app.example.com"],
            capture_output=True, text=True,
        )
        self.assertEqual(done.returncode, 1)
        verdict = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertFalse(verdict["ok"])


if __name__ == "__main__":
    unittest.main()
