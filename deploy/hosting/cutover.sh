#!/usr/bin/env bash
# Moves one BAPC VPN stage onto BAPC infrastructure: services on BAPC App Hosting (rootless Podman, managed by the
# host agent), database on BAPC Cheisgos, secrets from BAPC Secrets, image from the BAPC Registry.
# Run as root on the bapc-vpn server, inside a maintenance window for production:
#
#   bash cutover.sh staging|production sha256:<digest> <git sha>
#
# Before: deploy/hosting/README.md "One-time setup" is done (agent in apply mode, Cheisgos cluster, database and
# roles, secrets in BAPC Secrets, image built and promoted). The script checks what it can and stops otherwise.
#
#  1. production: a fresh verified backup of the current database.
#  2. stops the old stage (production: `docker compose stop`, containers kept for going back; staging: the systemd copy).
#  3. copies the data into the empty Cheisgos database (as its migrator role acting as the owner) and compares
#     table and migration counts.
#  4. deploy/hosting/release.mjs: vpn-api first (migrations), then the rest. Production waits for the owner's
#     approval in App Hosting ("Approve all 9" on the Approvals page).
#  5. checks the loopback ports and the public address, then points the nightly backup at Cheisgos.
# Any failure before step 5 starts the old stage again (App Hosting rolls its own rollouts back by itself; on the way
# back its apps must be scaled to 0 first, see README "Going back").
set -Eeuo pipefail
STAGE=${1:?usage: cutover.sh staging|production <digest> <sha>}
DIGEST=${2:?digest}
SHA=${3:?sha}
case "$STAGE" in production) S=prod; PORT_OFF=0; CLUSTER=vpn-core;; staging) S=staging; PORT_OFF=10000; CLUSTER=vpn-staging;; *) echo "stage?" >&2; exit 2;; esac
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "digest must be sha256:<64 hex>" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
DB=bapc_vpn; MIGRATOR=bapc_vpn_migrator
SECRET_FILE=/etc/bapc-sql/secrets/sql__bapc-vpn__${STAGE}__${CLUSTER}__${MIGRATOR}.v1
SETTINGS=/etc/bapc-vpn/hosting-$STAGE.json
# Cheisgos picks each cluster's port; the settings file records it ("db": {"port": ...}).
[ -s "$SETTINGS" ] && DBPORT=$(node -e 'const s=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(s.db?.port??""))' "$SETTINGS")
[ -n "$DBPORT" ] || { echo "settings need db.port (the Cheisgos cluster port)" >&2; exit 2; }
log(){ printf '%s cutover %s: %s\n' "$(date -u +%FT%TZ)" "$STAGE" "$*"; }
STOPPED=0
die(){ log "STOPPED: $*"; back; exit 1; }

back(){
  set +e
  [ "$STOPPED" = 1 ] || return
  log "GOING BACK: starting the old $STAGE again"
  if [ "$STAGE" = production ]; then (cd /opt/bapc-vpn/deploy && docker compose start); else systemctl start bapc-vpn@staging.target; fi
  log "old $STAGE started; if App Hosting containers hold its ports, scale the nine apps to 0 in App Hosting first (README)"
}

log "0/5 checks"
systemctl is-active -q bapc-host-agent || die "the App Hosting agent is not running (agent/machine/install.sh)"
pg_isready -q -h 127.0.0.1 -p "$DBPORT" || die "no Cheisgos PostgreSQL on 127.0.0.1:$DBPORT"
[ -s "$SECRET_FILE" ] || die "no Cheisgos migrator password at $SECRET_FILE (create the $MIGRATOR role in Cheisgos)"
[ -s "$SETTINGS" ] || die "no $SETTINGS"
[ -s /etc/bapc-vpn/host-client.env ] || die "no /etc/bapc-vpn/host-client.env (HOST_CLIENT_ID/HOST_CLIENT_SECRET)"
TARGET="host=127.0.0.1 port=$DBPORT dbname=$DB user=$MIGRATOR sslmode=require"
export PGPASSWORD; PGPASSWORD=$(cat "$SECRET_FILE")
TABLES=$(psql "$TARGET" -qtAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") || die "cannot sign in to Cheisgos as $MIGRATOR"
[ "$TABLES" = 0 ] || die "the Cheisgos database $DB already has $TABLES tables: refusing to copy over it"

WORK=$(mktemp -d /var/tmp/bapc-vpn-cutover.XXXXXX); chmod 700 "$WORK"
trap 'die "a step failed (line $LINENO)"' ERR
trap 'rm -rf "$WORK"' EXIT

COUNTS="SELECT (SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('bapc_security_core','public') AND table_type='BASE TABLE')||' '||(SELECT count(*) FROM public.schema_migrations)"
if [ "$STAGE" = production ]; then
  log "1/5 fresh verified backup"
  systemctl start bapc-vpn-backup.service || die "backup failed; nothing changed"
  log "2/5 stopping the Docker stack (containers kept)"
  (cd /opt/bapc-vpn/deploy && docker compose stop control-api customer-portal mesh-grpc oob-controller maintenance-worker soc-console secure-dns blind-relay egress-gateway)
  STOPPED=1
  (cd /opt/bapc-vpn/deploy && docker compose exec -T postgres pg_dump -U bapc_security -d bapc_security_core --format=custom --no-owner --no-privileges) > "$WORK/db.dump"
  OLD_COUNTS=$(cd /opt/bapc-vpn/deploy && docker compose exec -T postgres psql -U bapc_security -d bapc_security_core -qtAc "$COUNTS")
else
  log "1/5 (staging: no backup)"
  log "2/5 stopping the systemd staging copy"
  systemctl stop bapc-vpn@staging.target
  STOPPED=1
  OLD_URL=$(grep -E '^DATABASE_URL=' /etc/bapc-vpn/staging.env | cut -d= -f2-)
  ( unset PGPASSWORD; pg_dump --dbname="$OLD_URL" --format=custom --no-owner --no-privileges ) > "$WORK/db.dump"
  OLD_COUNTS=$( unset PGPASSWORD; psql "$OLD_URL" -qtAc "$COUNTS" )
fi
[ -s "$WORK/db.dump" ] || die "the dump is empty"

log "3/5 copying the data into Cheisgos ($DB on 127.0.0.1:$DBPORT) as the database owner"
PGOPTIONS="-c role=${DB}_owner" pg_restore --dbname="$TARGET" --no-owner --no-privileges --role="${DB}_owner" --exit-on-error < "$WORK/db.dump" || die "restore into Cheisgos failed"
NEW_COUNTS=$(psql "$TARGET" -qtAc "$COUNTS")
[ "$OLD_COUNTS" = "$NEW_COUNTS" ] || die "Cheisgos has '$NEW_COUNTS' tables/migrations, the old database '$OLD_COUNTS'"
log "copied: $NEW_COUNTS (tables, migrations)"
unset PGPASSWORD

log "4/5 releasing $SHA on App Hosting"
set -a; . /etc/bapc-vpn/host-client.env; set +a
node "$HERE/release.mjs" --stage "$STAGE" --digest "$DIGEST" --release "$SHA" --settings "$SETTINGS" || die "the release did not finish"

log "5/5 checks"
curl -fsS -o /dev/null "http://127.0.0.1:$((8080 + PORT_OFF))/healthz" || die "API /healthz failed"
curl -fsS -o /dev/null "http://127.0.0.1:$((8095 + PORT_OFF))/healthz" || die "portal /healthz failed"
PUBLIC=$([ "$STAGE" = production ] && echo https://vpn.bapc.app || echo https://staging-vpn.bapc.app)
curl -fsS -o /dev/null "$PUBLIC/" || die "$PUBLIC does not answer"
trap - ERR
if [ "$STAGE" = production ]; then
  log "pointing the nightly backup at Cheisgos (test restore on the local PostgreSQL)"
  umask 077
  { echo "DATABASE_URL=postgresql://$MIGRATOR:$(cat "$SECRET_FILE")@127.0.0.1:$DBPORT/$DB?sslmode=require"
    echo "DB_NAME=$DB"
    [ -s /etc/bapc-vpn-backup/check-url ] && echo "CHECK_DATABASE_URL=$(cat /etc/bapc-vpn-backup/check-url)"; } > /etc/bapc-vpn-backup/env.new
  mv /etc/bapc-vpn-backup/env.new /etc/bapc-vpn-backup/env
  systemctl start bapc-vpn-backup.service && log "backup from Cheisgos verified" || log "WARNING: the first backup from Cheisgos failed; check journalctl -u bapc-vpn-backup"
  log "Docker stack stopped but kept (going back: README). Remove it only after a quiet week, with the owner's yes."
fi
log "done: $STAGE runs on BAPC App Hosting + Cheisgos, release $SHA ($DIGEST)"
