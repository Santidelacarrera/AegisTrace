#!/usr/bin/env bash
# Logical backup of the AegisTrace database (events, alerts, incidents, users, audit chain).
#   DATABASE_URL=postgres://... ./scripts/backup.sh [outfile]      (docker: see docs/DEPLOYMENT.md)
# Also copy the audit anchor file and keep the AEGIS_* secrets in your secret manager: without AEGIS_AUDIT_KEY the
# audit chain cannot be verified, and without AEGIS_DATA_KEY the stored MFA seeds cannot be decrypted.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
OUT="${1:-aegistrace-$(date -u +%Y%m%dT%H%M%SZ).sql.gz}"
pg_dump --no-owner --no-privileges "$DATABASE_URL" | gzip -9 > "$OUT"
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
