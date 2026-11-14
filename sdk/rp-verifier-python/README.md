# datu-rp-verify

SignetAuth relying-party verifier for DATU, in pure Python (standard
library only; uses the `cryptography` package for Ed25519 when it is
installed, otherwise a compact RFC 8032 implementation).

Verifies the login assertion a Signet wallet returns for a
`datu-auth-v1` challenge, exactly the way `datu signet auth-verify`
and the browser SDK do: recompute the canonical signed bytes, check the
assertion matches the challenge you issued, check the challenge is
live, verify the Ed25519 signature against the identity public key.

## Install

Copy `datu_rp_verify.py` into your project, or

```sh
pip install datu-rp-verify   # once published
```

## Use

```python
from datu_rp_verify import new_challenge, verify_assertion

challenge = new_challenge(rp_id="app.example.com", origin="https://app.example.com")
# store the challenge (nonce single-use tracking is the RP's job), send it
# to the wallet, receive the assertion back, then:
result = verify_assertion(assertion, challenge, expected_pubkey=saved_key_hex)
if not result["ok"]:
    raise PermissionError(result["reason"])
# result["pubkey"] is the identity key that signed
```

`expected_pubkey` is optional: pass the key you have on file for that
account to reject assertions signed by any other identity.

## CLI

```sh
python3 datu_rp_verify.py --assertion assertion.json \
    --rp-id app.example.com --origin https://app.example.com
```

Exit code 0 with a JSON verdict when valid and live, exit 1 with the
rejection reason otherwise.

## Tests

```sh
python3 -m unittest discover -s sdk/rp-verifier-python
```

The suite pins RFC 8032 vectors and a fixture assertion minted by a
real Signet bridge (datu 0.2.0) for the spec's worked example, so the
canonical byte string stays identical across Rust, JS and Python.

MIT licensed, same as the rest of DATU.
