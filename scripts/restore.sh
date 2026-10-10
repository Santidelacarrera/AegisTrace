#!/usr/bin/env bash
# Restore a backup into an EMPTY database, then verify it:  DATABASE_URL=postgres://.../newdb ./scripts/restore.sh backup.sql.gz
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
FILE="${1:?usage: restore.sh <backup.sql.gz>}"
N=$(psql "$DATABASE_URL" -Atc "select count(*) from information_schema.tables where table_name in ('aegis_doc','aegis_audit')")
[ "$N" = "0" ] || { echo "refusing: target database already has AegisTrace tables" >&2; exit 1; }
gunzip -c "$FILE" | psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q
psql "$DATABASE_URL" -Atc "select 'documents', count(*) from aegis_doc union all select 'audit entries', count(*) from aegis_audit"
echo "restored. Start the API against this database and call GET /api/v1/audit/verify to confirm the audit chain."
