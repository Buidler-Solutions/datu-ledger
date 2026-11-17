-- Layer 2 example: one view over the projection's layer 1.
-- Apply after the indexer has projected at least one pass:
--   sqlite3 projection.db < examples/projection-titles/schema.sql
-- (PostgreSQL: json_extract -> payload::jsonb ->> 'parcel')
DROP VIEW IF EXISTS titles;
CREATE VIEW titles AS
SELECT id                                        AS ledger_entry_id,
       COALESCE(json_extract(payload, '$.parcel'), '')   AS parcel,
       COALESCE(json_extract(payload, '$.district'), '') AS district,
       author                                    AS signer,
       ts                                        AS recorded_at,
       namespace                                 AS ledger_namespace,
       ns_seq                                    AS namespace_ordinal
FROM entries
WHERE namespace LIKE 'gov.titles.%' AND payload IS NOT NULL;
