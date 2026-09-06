#!/usr/bin/env bash
# Backs up the BAPC security-core database and, if BACKUP_ENCRYPTION_KEY is set,
# encrypts the dump at rest with AES-256 via openssl. Requires pg_dump on PATH
# and DATABASE_URL to point at the target database.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
OUT_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP_FILE="${OUT_DIR}/bapc_security_core_${STAMP}.dump"

mkdir -p "${OUT_DIR}"
echo "Dumping ${DATABASE_URL%%\?*} -> ${DUMP_FILE}" >&2
pg_dump --format=custom --no-owner --no-privileges --file="${DUMP_FILE}" "${DATABASE_URL}"

if [[ -n "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
  openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_ENCRYPTION_KEY \
    -in "${DUMP_FILE}" -out "${DUMP_FILE}.enc"
  rm -f "${DUMP_FILE}"
  echo "Encrypted backup written to ${DUMP_FILE}.enc" >&2
else
  echo "WARNING: BACKUP_ENCRYPTION_KEY not set; backup left unencrypted at ${DUMP_FILE}" >&2
fi
