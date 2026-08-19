#!/usr/bin/env bash
# Dumps the shared Postgres instance (GoTrue's `auth` schema and IAM's
# `iam` schema together — see scripts/db-init.sh) to a timestamped,
# gzip-compressed file. Self-hosted Supabase ships with no built-in backup
# mechanism — this is the minimum viable one. Run it on a schedule
# (cron/systemd timer) and ship BACKUP_DIR's contents off this host; this
# script only produces the dump, it doesn't handle offsite storage. For
# point-in-time recovery instead of daily snapshots, look at WAL-G or
# pgBackRest.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
OUT_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

echo "==> Dumping db (${POSTGRES_DB:-postgres})"
docker compose -f "$COMPOSE_FILE" exec -T db pg_dump -U postgres -d "${POSTGRES_DB:-postgres}" \
  | gzip > "$OUT_DIR/db_${STAMP}.sql.gz"

echo "==> Wrote:"
ls -lh "$OUT_DIR/db_${STAMP}.sql.gz"
