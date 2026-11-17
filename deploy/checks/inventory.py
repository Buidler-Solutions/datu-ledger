#!/usr/bin/env python3
"""Dependency inventory (SBOM-lite) for the Rust workspace.

Reads `cargo metadata`, writes sbom-lite.json, prints a license summary and
fails when a copyleft license sneaks in. A full SPDX/CycloneDX SBOM is still
a follow-up; this is the cheap CI guard.
"""
import json
import subprocess
import sys
from collections import Counter

DENY = ("GPL-2.0", "GPL-3.0", "AGPL", "SSPL", "BUSL", "CC-BY-NC")

meta = json.loads(subprocess.run(
    ["cargo", "metadata", "--format-version", "1", "--all-features"],
    capture_output=True, text=True, check=True).stdout)

pkgs = []
licenses = Counter()
for p in meta["packages"]:
    lic = p.get("license") or "UNKNOWN"
    licenses[lic] += 1
    pkgs.append({"name": p["name"], "version": p["version"], "license": lic,
                 "source": p.get("source") or "workspace"})

sbom = {"format": "datu-sbom-lite/1", "packages": sorted(pkgs, key=lambda x: x["name"])}
with open("sbom-lite.json", "w", encoding="utf-8") as fh:
    json.dump(sbom, fh, indent=2)

print(f"{len(pkgs)} packages, {len(licenses)} distinct license strings")
for lic, n in licenses.most_common():
    print(f"  {n:4d}  {lic}")

bad = [p for p in pkgs if any(d in p["license"].upper() for d in DENY)]
unknown = [p for p in pkgs if p["license"] == "UNKNOWN"]
if bad:
    print("\nDENIED licenses:", *(f"{p['name']} {p['version']} ({p['license']})" for p in bad), sep="\n  ")
    sys.exit(1)
if unknown:
    print("\nwarning: packages without a license string:", *(p["name"] for p in unknown), sep="\n  ")
print("\nOK: no denied licenses; inventory written to sbom-lite.json")
