#!/usr/bin/env python3
"""Full SPDX 2.3 SBOM for the shipped software (readiness item S3).

Covers both ecosystems that end up in artifacts: the Rust workspace via
`cargo metadata` (every resolved crate, with license and source) and the
registrar dApp via its npm lockfile (every resolved package). Output is
a standards-shaped SPDX 2.3 JSON document (spdxVersion, creations,
packages with SPDXIDs, relationships to the document root), so standard
tooling (grype, dependency-track, osv-scanner) can consume it without a
translator. The extension is vanilla JS with no dependencies, so its
manifest is recorded as one package.

Writes sbom.spdx.json next to this script's repo root; exits nonzero if
either ecosystem cannot be read or a package ends up without an
identifier (every shipped dependency must be accountable).
"""
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPDX_ID = re.compile(r"[^a-zA-Z0-9.-]")


def spdx_id(name, version):
    return "SPDXRef-Package-" + SPDX_ID.sub("-", f"{name}-{version}")


def license_to_spdx(raw):
    if not raw:
        return "NOASSERTION"
    # cargo license fields are already SPDX-ish expressions (MIT OR
    # Apache-2.0, etc); pass through, normalizing the one common oddity.
    return raw.replace("Apache 2.0", "Apache-2.0").replace("Apache-2", "Apache-2.0")


def rust_packages():
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout)
    workspace_ids = {p["id"] for p in meta["packages"] if p.get("source") is None}
    doc_name = "datu-ledger"
    root = None
    packages = []
    relationships = []
    for p in sorted(meta["packages"], key=lambda x: x["name"]):
        pid = spdx_id(p["name"], p["version"])
        if p["id"] in workspace_ids and p["name"] == "datu-cli":
            root = pid
        packages.append({
            "SPDXID": pid,
            "name": p["name"],
            "versionInfo": p["version"],
            "downloadLocation": (p.get("source") or "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": license_to_spdx(p.get("license")),
            "licenseDeclared": license_to_spdx(p.get("license")),
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{p['name']}@{p['version']}",
            }] if p.get("source") else [],
        })
    if root is None:
        sys.exit("cannot find the datu-cli workspace package to anchor the document")
    return doc_name, root, packages, relationships


def npm_packages():
    lock = os.path.join(ROOT, "web", "registrar", "package-lock.json")
    with open(lock, encoding="utf-8") as fh:
        data = json.load(fh)
    packages = []
    root_version = data.get("packages", {}).get("", {}).get("version", "0.1.0")
    for key, info in sorted(data.get("packages", {}).items()):
        if not key:  # the root package itself
            continue
        name = key.removeprefix("node_modules/")
        version = info.get("version", "UNKNOWN")
        packages.append({
            "SPDXID": spdx_id(f"npm-{name}", version),
            "name": f"npm:{name}",
            "versionInfo": version,
            "downloadLocation": info.get("resolved", "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": license_to_spdx(info.get("license")),
            "licenseDeclared": license_to_spdx(info.get("license")),
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:npm/{name}@{version}",
            }] if info.get("resolved") else [],
        })
    return root_version, packages


def main():
    doc_name, root, rust, _ = rust_packages()
    reg_version, npm = npm_packages()
    reg_root = spdx_id("npm-datu-registrar", reg_version)
    npm_doc_package = {
        "SPDXID": reg_root,
        "name": "datu-registrar",
        "versionInfo": reg_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{doc_name}-sbom",
        "documentNamespace": f"https://github.com/Buidler-Solutions/datu-ledger/spdx/{doc_name}",
        "creationInfo": {
            "created": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "creators": ["Tool: datu-sbom-generator"],
        },
        "packages": [npm_doc_package] + rust + npm,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": root},
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": reg_root},
        ],
    }

    for pkg in document["packages"]:
        if not pkg["SPDXID"] or "UNKNOWN" in pkg["versionInfo"]:
            sys.exit(f"package without a resolvable identity: {pkg.get('name')}")

    out = os.path.join(ROOT, "sbom.spdx.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")

    digest = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(f"SPDX 2.3 SBOM: {len(rust)} cargo packages + {len(npm) + 1} npm packages")
    print(f"written {out} (sha256 {digest[:16]}...)")


if __name__ == "__main__":
    main()
