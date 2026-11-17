#!/usr/bin/env python3
"""Deterministic tar.gz for release artifacts (readiness item O2).

GNU tar's --sort/--mtime flags do not exist on bsdtar (the macOS
runners), and tarfile's gzip container stamps the wall clock into bytes
4-8, so an archive built from identical inputs would still hash
differently per run. This helper sorts entries, pins mtimes/owners to
the epoch, and zeroes the gzip mtime, making the archive hash a pure
function of its contents.

Usage: deterministic-tar.py <srcdir> <name>   (writes <srcdir>/<name>.tar.gz)
"""

import gzip
import os
import sys
import tarfile


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    srcdir, name = sys.argv[1], sys.argv[2]
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1"))
    out = os.path.join(srcdir, f"{name}.tar.gz")
    with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as tar:
        for root, dirs, files in os.walk(os.path.join(srcdir, name)):
            dirs.sort()
            for fname in sorted(files):
                path = os.path.join(root, fname)
                info = tar.gettarinfo(path, arcname=os.path.relpath(path, srcdir))
                info.mtime = epoch
                info.uname = info.gname = ""
                info.uid = info.gid = 0
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
    with open(out, "rb") as fh:
        blob = fh.read()
    with gzip.GzipFile(filename="", mode="wb", fileobj=open(out, "wb"), mtime=0) as gz:
        gz.write(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
