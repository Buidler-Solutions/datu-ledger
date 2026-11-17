# Projection deployment (node + indexer + PostgreSQL)

One compose stack builds `datu` and `datu-indexer` from this repository,
runs a witness node, projects its verified entries into PostgreSQL, and
keeps both alive.

```bash
cp deploy/projection/.env.example deploy/projection/.env
$EDITOR deploy/projection/.env            # set DATU_SEED and PG_PASSWORD
docker compose -f deploy/projection/docker-compose.yml up -d --build
docker compose -f deploy/projection/docker-compose.yml logs -f indexer
```

Health: the indexer prints a pass line per cycle; the JSON view is available
inside the container:

```bash
docker compose -f deploy/projection/docker-compose.yml exec indexer \
  datu-indexer --db-url postgres://datu:$PG_PASSWORD@db:5432/datu --status
```

For a bare-metal host, use `datu-indexer.service` (a `systemd --user` unit)
plus the node runbook from the user manual, chapters 16-18.

Notes:
- the indexer reads the node's `node.db` from a shared volume; SQLite WAL
  allows concurrent readers, so it never blocks the node
- layer 2 (app tables) is yours: apply SQL like
  `examples/projection-titles/schema.sql` to the same database
- `DATU_NAMESPACES` takes a single pattern here; edit the compose command
  for several (`--namespace` is repeatable)
