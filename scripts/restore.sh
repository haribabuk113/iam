#!/usr/bin/env bash
# Restores one dump produced by backup.sh into a running compose stack.
# Overwrites existing data in the target database — there's no
# confirmation prompt, this is meant to be scriptable.
#
# Usage:
#   scripts/restore.sh ./backups/db_20260819T120000Z.sql.gz
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
DUMP="${1:?usage: restore.sh <dump-file.sql.gz>}"

echo "==> Restoring $DUMP into db (${POSTGRES_DB:-postgres}) — this overwrites existing data"
gunzip -c "$DUMP" | docker compose -f "$COMPOSE_FILE" exec -T db psql -U postgres -d "${POSTGRES_DB:-postgres}"
echo "==> Done"
