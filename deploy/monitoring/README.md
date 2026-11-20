# Monitoring the projection indexer

The indexer exposes Prometheus metrics when started with `--http`:

```bash
datu-indexer --data-dir /var/lib/datu/node \
  --db-url "$DATU_DB_URL" \
  --every 5 --http 127.0.0.1:7491
# /healthz  JSON status
# /metrics  Prometheus text
```

Ship `prometheus.yml` and `alerts.yml` with your Prometheus. Alerts cover the
three failures that matter: a stale projection (lag), verification rejections
(fail-closed, never ignore), and a dead metrics endpoint.

The node itself exposes `/v1/status` over its HTTP API; scrape it with a
blackbox exporter if you want node-level alerts (entries, checkpoints,
peers synced) alongside the indexer's.
