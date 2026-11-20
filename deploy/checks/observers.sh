#!/usr/bin/env bash
# Who on this machine is serving an explorer? Every `serve` or `node --http`
# exposes the full UI, so a pile of test runs looks like the explorer
# "replicating". This probes each datu listener for /v1/status and prints
# the owner, so ending the noise is one visible decision.
set -euo pipefail
found=0
for pid in $(pgrep -x datu || true); do
  while IFS= read -r port; do
    [ -n "$port" ] || continue
    code=$(python3 - "$port" <<'PY' 2>/dev/null || true
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5) as s:
        s.sendall(b"GET /v1/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        print("200" if b"200 OK" in s.recv(200) else "")
except Exception:
    print("")
PY
)
    if [ "$code" = "200" ]; then
      cmd=$(ps -o command= -p "$pid" | cut -c1-140)
      echo "explorer  port $port  pid $pid  $cmd"
      found=$((found+1))
    fi
  done < <(lsof -nP -a -p "$pid" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {split($9,a,":"); print a[length(a)]}' | sort -u)
done
if [ "$found" -eq 0 ]; then echo "no explorer endpoints on this machine"; else echo "$found explorer endpoint(s)"; fi
