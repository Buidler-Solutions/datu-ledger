# Release signing and verification (readiness item O2)

What a release ships, how to verify it, and how to rebuild it bit for
bit. The trust chain: checksums catch transport corruption and casual
tampering; the Sigstore signature proves the checksums came from this
repo's release pipeline; the reproducible build lets anyone verify the
binaries against the tag without trusting the pipeline at all.

## What a release contains

- `datu-<tag>-<target>.tar.gz` - the `datu` binary + README + LICENSE
  per target (linux gnu, linux musl, macOS x86_64, macOS arm64)
- `datu-<tag>-<target>.tar.gz.sha256` - per-archive checksums
- web bundles (Signet extension, registrar dApp)
- `SHA256SUMS` - checksums over every artifact
- `SHA256SUMS.sig` + `SHA256SUMS.pem` - Sigstore signature and the
  certificate that signed it

## Verify a download

```bash
# 1. integrity: the bytes match the published checksums
grep "datu-v0.2.0-x86_64-apple-darwin.tar.gz" SHA256SUMS | shasum -a 256 --check

# 2. provenance: the checksums were signed by this repo's pipeline
cosign verify-blob \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.pem \
  --certificate-identity-regexp "^https://github.com/greenarmor/datu-ledger/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

The signing is keyless: cosign exchanges the workflow's OIDC token for a
short-lived certificate, so there is no signing key to leak or rotate.
The identity check is what binds the signature to this repository - a
valid cosign signature from some other workflow proves nothing.

## Reproduce the build (no trust in the pipeline needed)

The release binaries and archives are deterministic: same tag, same
toolchain, same bytes. Locally:

```bash
./deploy/checks/reproducible.sh
```

builds the tag twice from two different checkout paths and compares
hashes. To compare against a downloaded artifact directly, build with
the same recipe the release uses and check the binary inside the
archive:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
RUSTFLAGS="--remap-path-prefix=$(pwd)=/usr/src/datu --remap-path-prefix=$HOME/.cargo/registry=/usr/src/cargo" \
  cargo build --release --locked -p datu-cli --target <target>
```

The two remap destinations (`/usr/src/datu`, `/usr/src/cargo`) and the
pinned `SOURCE_DATE_EPOCH` are the recipe; changing any of them changes
the bytes. The reproducible-build gate runs on every push in CI.

## Upgrading to a hardware signing key

If a deployment ever requires a long-lived identity instead of keyless,
sign `SHA256SUMS` with minisign or a YubiKey-held key and publish the
`.minisig` plus the public key in the repo; keep the keyless signature
as well so both verification paths work. The release workflow needs no
secrets today - keep it that way unless this path is taken.
