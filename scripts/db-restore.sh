#!/usr/bin/env bash
# Restores a backup produced by db-backup.sh into DATABASE_URL.
# Usage: BACKUP_ENCRYPTION_KEY=... ./scripts/db-restore.sh backups/bapc_security_core_TIMESTAMP.dump[.enc]
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
INPUT="${1:?path to a .dump or .dump.enc file is required}"
WORK_FILE="${INPUT}"

if [[ "${INPUT}" == *.enc ]]; then
  : "${BACKUP_ENCRYPTION_KEY:?BACKUP_ENCRYPTION_KEY is required to decrypt ${INPUT}}"
  WORK_FILE="${INPUT%.enc}"
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY -in "${INPUT}" -out "${WORK_FILE}"
fi

echo "Restoring ${WORK_FILE} -> ${DATABASE_URL%%\?*}" >&2
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="${DATABASE_URL}" "${WORK_FILE}"

if [[ "${WORK_FILE}" != "${INPUT}" ]]; then
  rm -f "${WORK_FILE}"
fi
echo "Restore complete. Run 'npm run migrate:status' to confirm schema version." >&2
