#!/usr/bin/env python3
"""Read-only HTTP API over the projection's titles view (stdlib only).

    python3 examples/projection-titles/server.py \
        --db /tmp/datu-demo/projection.db --port 7490

    curl -s http://127.0.0.1:7490/healthz
    curl -s "http://127.0.0.1:7490/titles?limit=5"

It is deliberately small: the projection is a plain SQLite file, so any
language can do this. Swap sqlite3 for psycopg to serve the PostgreSQL
projection instead.
"""
import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def open_db(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="projection sqlite file")
    ap.add_argument("--port", type=int, default=7490)
    ap.add_argument("--origin", default="*", help="CORS origin for the dApp")
    args = ap.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body):
            payload = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", args.origin)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                conn = open_db(args.db)
            except Exception as e:  # noqa: BLE001 - report, never crash the server
                return self._send(503, {"error": f"cannot open projection: {e}"})
            try:
                if url.path == "/healthz":
                    row = conn.execute(
                        "SELECT COALESCE(cursor_ord,0) AS cursor, "
                        "COALESCE(checkpoint_height,0) AS height, "
                        "COALESCE(updated_at_ms,0) AS updated "
                        "FROM indexer_state WHERE stream='layer1'"
                    ).fetchone()
                    count = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                    titles = conn.execute("SELECT COUNT(*) FROM titles").fetchone()[0] \
                        if _has_view(conn) else 0
                    return self._send(200, {
                        "entries": count,
                        "titles": titles,
                        "cursor": f"cur1:{row['cursor']}" if row else "cur1:0",
                        "checkpoint_height": row["height"] if row else 0,
                        "updated_at_ms": row["updated"] if row else 0,
                    })
                if url.path == "/titles":
                    if not _has_view(conn):
                        return self._send(424, {
                            "error": "titles view missing - apply examples/projection-titles/schema.sql",
                        })
                    limit = min(int(q.get("limit", ["50"])[0]), 500)
                    offset = max(int(q.get("offset", ["0"])[0]), 0)
                    rows = conn.execute(
                        "SELECT * FROM titles ORDER BY recorded_at DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    ).fetchall()
                    return self._send(200, {
                        "titles": [dict(r) for r in rows],
                        "limit": limit,
                        "offset": offset,
                    })
                return self._send(404, {"error": "not found", "paths": ["/healthz", "/titles"]})
            finally:
                conn.close()

        def log_message(self, fmt, *a):  # quiet default logging
            pass

    def _has_view(conn):
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='view' AND name='titles'"
        ).fetchone() is not None

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"projection read API on http://127.0.0.1:{args.port} (db {args.db})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
