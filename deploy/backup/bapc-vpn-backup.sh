#!/usr/bin/env bash
# Nightly verified backup of the BAPC VPN database (bapc_security_core).
# Runs on the VPN server from bapc-vpn-backup.timer (03:15 UTC). Each run:
#   1. pg_dump (custom format) of the live database,
#   2. checks the archive reads back (pg_restore --list),
#   3. restores it into a throwaway database, compares table and migration
#      counts with the live one, then drops the throwaway database,
#   4. encrypts it (AES-256, the same format as scripts/db-backup.sh) and
#      checks the encrypted file decrypts to the same bytes,
#   5. writes /var/backups/bapc-vpn/<UTC stamp>/{db.dump.enc,manifest.json,VERIFIED},
#   6. deletes local copies older than KEEP_DAYS,
#   7. sends the newest copy to BAPC Backup (https://backup.bapc.app/ingest/bapc-vpn)
#      when /etc/bapc-vpn-backup/token exists. Backup reads it back, checks
#      it, and flags it on its health page (and Status) if it is missing or
#      more than 26 hours old.
# No unencrypted copy is ever kept: the plain dump only exists in a root-only
# work folder that is removed when the run ends.
#
# Database access: by default through the Docker Compose stack in
# COMPOSE_DIR (the current deployment). Set DATABASE_URL instead to use host
# pg_dump/pg_restore/psql once the stack runs without Docker.
#
# Restore a copy:  BACKUP_ENCRYPTION_KEY=... scripts/db-restore.sh <folder>/db.dump.enc
set -euo pipefail

CONF=${BAPC_VPN_BACKUP_CONF:-/etc/bapc-vpn-backup}
DIR=${BACKUP_DIR:-/var/backups/bapc-vpn}
KEEP_DAYS=${KEEP_DAYS:-14}
COMPOSE_DIR=${COMPOSE_DIR:-/opt/bapc-vpn/deploy}
DB=${DB_NAME:-bapc_security_core}
DB_USER=${DB_USER:-bapc_security}
CHECK_DB=bapc_vpn_restore_check
BACKUP_URL=${BAPC_BACKUP_URL:-https://backup.bapc.app}
LABEL=bapc-vpn

log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
die(){ log "FAILED: $*"; exit 1; }

[ -s "$CONF/key" ] || die "no encryption key at $CONF/key"
BACKUP_ENCRYPTION_KEY=$(cat "$CONF/key"); export BACKUP_ENCRYPTION_KEY

# Postgres client tools against the VPN database server. $1 is the tool,
# $2 the database to connect to, the rest are passed through.
pgtool(){
  local tool=$1 db=$2; shift 2
  if [ -n "${DATABASE_URL:-}" ]; then
    local base=${DATABASE_URL%/*}
    "$tool" --dbname="$base/$db" "$@"
  else
    (cd "$COMPOSE_DIR" && docker compose exec -T postgres "$tool" -U "$DB_USER" --dbname="$db" "$@")
  fi
}
pgplain(){ # same, for tools that take no --dbname (pg_restore --list)
  if [ -n "${DATABASE_URL:-}" ]; then "$@"; else (cd "$COMPOSE_DIR" && docker compose exec -T postgres "$@"); fi
}
sql(){ pgtool psql "$1" -v ON_ERROR_STOP=1 -qtAc "$2"; }
COUNTS="SELECT (SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('bapc_security_core','public') AND table_type='BASE TABLE')||' '||(SELECT count(*) FROM public.schema_migrations)"

umask 077
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK="$DIR/.work-$STAMP"
mkdir -p "$WORK"
cleanup(){ rm -rf "$WORK"; sql postgres "DROP DATABASE IF EXISTS $CHECK_DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "dumping $DB"
pgtool pg_dump "$DB" --format=custom --no-owner --no-privileges > "$WORK/db.dump"
[ -s "$WORK/db.dump" ] || die "pg_dump produced an empty file"
LIVE_COUNTS=$(sql "$DB" "$COUNTS")

log "checking the archive reads back"
ENTRIES=$(pgplain pg_restore --list < "$WORK/db.dump" | grep -vc '^;' || true)
[ "${ENTRIES:-0}" -gt 0 ] || die "pg_restore could not read the archive"

log "test restore into $CHECK_DB"
sql postgres "DROP DATABASE IF EXISTS $CHECK_DB"
sql postgres "CREATE DATABASE $CHECK_DB"
pgtool pg_restore "$CHECK_DB" --no-owner --no-privileges --exit-on-error < "$WORK/db.dump" \
  || die "test restore failed"
RESTORED_COUNTS=$(sql "$CHECK_DB" "$COUNTS")
sql postgres "DROP DATABASE $CHECK_DB"
# Live counts are read just after the dump, so a migration landing in
# between could differ; nothing migrates at 03:15, so treat any gap as a failure.
[ "$LIVE_COUNTS" = "$RESTORED_COUNTS" ] || die "restored copy has '$RESTORED_COUNTS' tables/migrations, live has '$LIVE_COUNTS'"
read -r TABLES MIGRATIONS <<<"$RESTORED_COUNTS"

log "encrypting"
openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_ENCRYPTION_KEY -in "$WORK/db.dump" -out "$WORK/db.dump.enc"
PLAIN_SHA=$(sha256sum "$WORK/db.dump" | cut -d' ' -f1)
CHECK_SHA=$(openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_KEY -in "$WORK/db.dump.enc" | sha256sum | cut -d' ' -f1)
[ "$PLAIN_SHA" = "$CHECK_SHA" ] || die "encrypted copy does not decrypt to the dump"
rm -f "$WORK/db.dump"
ENC_SHA=$(sha256sum "$WORK/db.dump.enc" | cut -d' ' -f1)
BYTES=$(stat -c %s "$WORK/db.dump.enc")

cat > "$WORK/manifest.json" <<JSON
{"system":"bapc-vpn-and-digital-security","database":"$DB","created":"$STAMP","file":"db.dump.enc",
 "encryption":"openssl aes-256-cbc pbkdf2","bytes":$BYTES,"sha256":"$ENC_SHA","dump_sha256":"$PLAIN_SHA",
 "archive_entries":$ENTRIES,"tables":$TABLES,"migrations":$MIGRATIONS,"test_restore":"passed"}
JSON
touch "$WORK/VERIFIED"
mv "$WORK" "$DIR/$STAMP"
log "verified backup $DIR/$STAMP ($BYTES bytes, $TABLES tables, $MIGRATIONS migrations)"

find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '20*Z' -mtime +"$KEEP_DAYS" -exec rm -rf {} + || true

if [ ! -s "$CONF/token" ]; then
  log "WARNING: offsite copy not configured ($CONF/token missing); the only copies are on this server"
  exit 0
fi
TAR="$DIR/.offsite-$STAMP.tar.gz"
tar -czf "$TAR" -C "$DIR" "$STAMP"
SUM=$(sha256sum "$TAR" | cut -d' ' -f1)
CODE=$(curl -sS -o "$DIR/.offsite-$STAMP.out" -w '%{http_code}' --max-time 300 -X POST "$BACKUP_URL/ingest/$LABEL" \
  -H "authorization: Bearer $(cat "$CONF/token")" -H "x-backup-sha256: $SUM" -H "x-backup-source: $STAMP" \
  -H 'content-type: application/gzip' --data-binary "@$TAR") || CODE=000
log "offsite copy -> HTTP $CODE $(cat "$DIR/.offsite-$STAMP.out" 2>/dev/null)"
rm -f "$TAR" "$DIR/.offsite-$STAMP.out"
[ "$CODE" = 200 ] || die "offsite copy was not accepted"
