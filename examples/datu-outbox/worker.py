#!/usr/bin/env python3
"""Rung-1 outbox worker (stdlib only).

Drains `datu_outbox` rows by signing them with a local node identity and
submitting to any accepting node:

    python3 examples/datu-outbox/worker.py \
        --db /var/lib/app/app.db \
        --datu /usr/local/bin/datu \
        --data-dir /var/lib/datu/authority \
        --node http://127.0.0.1:7474 \
        --every 5

The app writes business rows and outbox rows in one transaction; this worker
publishes and writes back `entry_id`/`state`. An unreachable ledger becomes a
growing queue, never a broken application. If the app should sign through a
Signet instead of a node key, swap `publish()` for a bridge call; the outbox
schema stays the same.
"""
import argparse
import re
import sqlite3
import subprocess
import time


ID_RE = re.compile(r"\b([0-9a-f]{64})\b")


def publish(args, ns, payload):
    """Publish one payload with the authority node's own key."""
    out = subprocess.run(
        [args.datu, "--data-dir", args.data_dir, "publish",
         "--ns", ns, "--payload", payload],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout).strip()[:300])
    match = ID_RE.search(out.stdout)
    if not match:
        raise RuntimeError(f"no entry id in output: {out.stdout.strip()[:200]}")
    return match.group(1)


def submit(node, entry_json):  # kept for the signet variant
    import urllib.request
    req = urllib.request.Request(
        f"{node.rstrip('/')}/v1/entries",
        data=entry_json.encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return res.read().decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="application database (sqlite)")
    ap.add_argument("--datu", default="datu", help="datu binary path")
    ap.add_argument("--data-dir", required=True, help="authority node data dir")
    ap.add_argument("--node", default="", help="also POST to this node (optional)")
    ap.add_argument("--every", type=int, default=5)
    ap.add_argument("--max-attempts", type=int, default=5)
    args = ap.parse_args()

    while True:
        conn = sqlite3.connect(args.db)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM datu_outbox WHERE state = 'pending' ORDER BY id LIMIT 1"
            ).fetchone()
            if not row:
                time.sleep(args.every)
                continue
            try:
                entry_id = publish(args, row["namespace"], row["payload"])
                conn.execute(
                    "UPDATE datu_outbox SET state='signed', entry_id=?, updated_at_ms=?,"
                    " last_error=NULL WHERE id=?",
                    (entry_id, int(time.time() * 1000), row["id"]),
                )
                conn.commit()
                print(f"outbox {row['id']}: signed {row['kind']} -> {entry_id[:16]}…")
            except Exception as e:  # noqa: BLE001 - queue, retry, never crash
                attempts = row["attempts"] + 1
                state = "failed" if attempts >= args.max_attempts else "pending"
                conn.execute(
                    "UPDATE datu_outbox SET state=?, attempts=?, last_error=?,"
                    " updated_at_ms=? WHERE id=?",
                    (state, attempts, str(e)[:300], int(time.time() * 1000), row["id"]),
                )
                conn.commit()
                print(f"outbox {row['id']}: attempt {attempts} failed: {e}")
                time.sleep(args.every)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
