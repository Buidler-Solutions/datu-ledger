#!/usr/bin/env python3
"""Legal-basis register gate.

Every processing activity the software knows about must appear in
compliance/legal-bases.json with a GDPR article, a DPA 2012 counterpart, an
evidence pointer that exists in the repository, and a retention statement.
A new namespace or subsystem without a register entry is a compliance bug,
so this runs in CI next to the other gates.

Run locally:  python3 deploy/checks/legal-bases.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "compliance" / "legal-bases.json"

# Activities the codebase implements today. Adding a subsystem means adding a
# row here and a register entry, in the same change.
REQUIRED = {
    "identity-attestation",
    "enrollment-ceremony",
    "guardian-recovery",
    "party-signed-records",
    "witness-checkpoints",
    "signet-auth-login",
    "http-request-logs",
    "local-provenance",
    "sealed-documents",
    "projection-index",
}

ARTICLE_RE = re.compile(r"^6\(1\)\([a-f]\)(\s*[;,]\s*6\(1\)\([a-f]\))*$")


def main() -> int:
    if not REGISTER.exists():
        print(f"legal-bases: missing {REGISTER.relative_to(ROOT)}", file=sys.stderr)
        return 1
    try:
        doc = json.loads(REGISTER.read_text())
    except json.JSONDecodeError as e:
        print(f"legal-bases: {REGISTER.relative_to(ROOT)} is not valid JSON: {e}", file=sys.stderr)
        return 1

    problems: list[str] = []
    activities = doc.get("activities")
    if not isinstance(activities, list) or not activities:
        print("legal-bases: no activities registered", file=sys.stderr)
        return 1
    seen: set[str] = set()
    for i, a in enumerate(activities):
        where = f"activities[{i}]"
        if not isinstance(a, dict):
            problems.append(f"{where}: not an object")
            continue
        ident = a.get("id")
        if not ident:
            problems.append(f"{where}: missing id")
            continue
        where = f"{ident}"
        if ident in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(ident)
        for field in ("activity", "description", "retention", "recipients"):
            if not str(a.get(field, "")).strip():
                problems.append(f"{where}: missing {field}")
        categories = a.get("data_categories")
        if not isinstance(categories, list) or not categories:
            problems.append(f"{where}: missing data_categories")
        basis = a.get("legal_basis") or {}
        if not basis.get("regulation"):
            problems.append(f"{where}: missing legal_basis.regulation")
        article = str(basis.get("article", "")).strip()
        if not ARTICLE_RE.match(article):
            problems.append(
                f"{where}: legal_basis.article {article!r} is not a GDPR Art. 6(1) pattern"
            )
        if not str(basis.get("name", "")).strip():
            problems.append(f"{where}: missing legal_basis.name")
        if not str(basis.get("ph_dpa", "")).strip():
            problems.append(f"{where}: missing legal_basis.ph_dpa (DPA 2012 counterpart)")
        evidence = a.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            problems.append(f"{where}: missing evidence pointers")
        else:
            for pointer in evidence:
                # Pointers are repo paths or `tests: <name>` references.
                if str(pointer).startswith("tests:"):
                    name = str(pointer).split(":", 1)[1].strip()
                    if name not in (ROOT / "crates" / "cli" / "src" / "main.rs").read_text():
                        problems.append(f"{where}: test {name!r} not found in cli tests")
                    continue
                if not (ROOT / pointer).exists():
                    problems.append(f"{where}: evidence path {pointer!r} does not exist")

    missing = REQUIRED - seen
    for ident in sorted(missing):
        problems.append(f"required activity {ident!r} has no register entry")
    extra = seen - REQUIRED
    for ident in sorted(extra):
        print(f"note: {ident} is registered but not in the required list (fine if intentional)")

    if problems:
        print("\nlegal-bases FAILED:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"legal-bases: PASS ({len(activities)} activities, all with basis, notice evidence and retention)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
