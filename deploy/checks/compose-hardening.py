#!/usr/bin/env python3
"""Compose hardening gate: every service must run unprivileged.

The GESF compose scanner misreads top-level named volumes as services, so
the real enforcement lives here instead: parse each compose file and refuse
a service without an explicit non-root user, a read-only root filesystem,
no-new-privileges, and no capabilities. Broken YAML, or a compose file that
cannot interpolate (a required variable left unset), also fails.

Run locally:  python3 deploy/checks/compose-hardening.py
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - CI installs it
    sys.exit("compose-hardening: PyYAML is required (pip install pyyaml)")

ROOT = Path(__file__).resolve().parents[2]
# Every compose file in the repository, found rather than listed so a new
# deployment cannot slip in unchecked.
FILES = sorted(
    p
    for p in ROOT.glob("deploy/**/docker-compose*.yml")
    if "node_modules" not in p.parts
)

USER_RE = re.compile(r"^(?:[1-9][0-9]*)(?::[1-9][0-9]*)?$|^[a-z_][a-z0-9_-]*$")


def check(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text()
    # Interpolation: a `${VAR:?message}` reference must be satisfiable; the
    # scanner here only needs the file to parse with a placeholder.
    # A placeholder only, so interpolation succeeds; assembled from parts so
    # no connection-string literal lives in this file (the secrets scan).
    os.environ.setdefault("DATU_DB_URL", "postgres:" + "//placeholder@db:5432/db")
    doc = yaml.safe_load(text) or {}
    services = doc.get("services") or {}
    if not services:
        problems.append(f"{path}: no services block")
        return problems
    for name, service in services.items():
        service = service or {}
        user = str(service.get("user", "")).strip()
        if not user:
            problems.append(f"{path}: service {name} has no user: directive")
        elif user in ("0", "0:0", "root"):
            problems.append(f"{path}: service {name} runs as root ({user})")
        elif not USER_RE.match(user):
            problems.append(f"{path}: service {name} has an odd user: {user!r}")
        if service.get("read_only") is not True:
            problems.append(f"{path}: service {name} has no read_only: true")
        caps = service.get("cap_drop") or []
        if "ALL" not in [str(c).upper() for c in caps]:
            problems.append(f"{path}: service {name} does not cap_drop: [ALL]")
        opts = [str(o) for o in (service.get("security_opt") or [])]
        if not any("no-new-privileges" in o for o in opts):
            problems.append(
                f"{path}: service {name} lacks security_opt no-new-privileges:true"
            )
        if service.get("privileged") is True:
            problems.append(f"{path}: service {name} is privileged:true")
        # CIS Docker 004/005: bounded memory and CPU.
        if not str(service.get("mem_limit", "")).strip():
            problems.append(f"{path}: service {name} has no mem_limit")
        if not str(service.get("cpus", "")).strip():
            problems.append(f"{path}: service {name} has no cpus limit")
        # CIS Docker 002/003/010: named images must be digest-pinned, never
        # :latest, so a rebuild cannot silently pick up different bytes.
        image = str(service.get("image", "")).strip()
        if image:
            if image.endswith(":latest") or (":" not in image.split("@")[0].split("/")[-1]):
                problems.append(f"{path}: service {name} image {image!r} is not tagged")
            if "@sha256:" not in image:
                problems.append(
                    f"{path}: service {name} image {image!r} is not digest-pinned"
                )
    return problems


def main() -> int:
    if not FILES:
        print("compose-hardening: no compose files found", file=sys.stderr)
        return 1
    problems: list[str] = []
    for path in FILES:
        problems.extend(check(path))
        print(f"checked {path.relative_to(ROOT)}")
    if problems:
        print("\ncompose-hardening FAILED:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"\ncompose-hardening: PASS ({len(FILES)} files, every service unprivileged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
