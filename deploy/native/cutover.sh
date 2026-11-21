#!/usr/bin/env bash
# One-time move of PRODUCTION from Docker Compose to the systemd layout, with the database moved from the Postgres 17
# container into the host's PostgreSQL 18. Same ports, so the Cloudflare tunnel, the WireGuard gateway and its sync
# keep working unchanged. Needs the owner's yes and a short maintenance window (customers' VPN tunnels keep running:
# WireGuard is on the host; only sign-in, device changes and payment updates pause for a minute or two).
#
# Before: bash deploy/native/setup-host.sh prod   (packages, user, units, empty bapc_security_core on host PG 18)
# Run detached so a dropped SSH connection can't stop it halfway:
#   systemd-run --unit=bapc-vpn-cutover bash cutover.sh /opt/bapc-vpn-releases/bapc-vpn-<sha>.tar.gz <sha>
#
# Steps (any failure after the Docker services stop puts Docker back exactly as it was):
#  1. fresh verified backup of the Docker database (bapc-vpn-backup, Docker mode)
#  2. builds the release into /opt/bapc-vpn-native/prod (BUILD_ONLY: nothing starts) while Docker still serves
#  3. writes /etc/bapc-vpn/prod.env from the Docker deploy/.env (same secrets) + the host database URL
#  4. stops the Docker app services (Postgres container stays up)               <- downtime starts
#  5. dumps the container database and restores it into host PostgreSQL 18; table, migration and row counts must match
#  6. starts bapc-vpn@prod.target and checks every unit, /healthz and the portal  <- downtime ends
#  7. points the gateway sync and the nightly backup at the new settings and database
#  8. stops the Docker Postgres container (kept, not deleted: removing Docker is a separate step with the owner's yes)
set -Eeuo pipefail
BUNDLE=${1:?usage: cutover.sh <bundle.tar.gz> <sha>}
SHA=${2:?sha}
HERE="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR=/opt/bapc-vpn/deploy
DENV=$DOCKER_DIR/.env
ENV_FILE=/etc/bapc-vpn/prod.env
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DUMP=/var/backups/bapc-vpn/cutover-$STAMP.dump
APP_SERVICES=(control-api customer-portal mesh-grpc oob-controller maintenance-worker soc-console secure-dns blind-relay egress-gateway)
TABLES=(mesh_nodes devices customer_devices enrollment_invites portal_audit portal_sessions audit_chain certificates)
log(){ printf '%s cutover %s: %s\n' "$(date -u +%FT%TZ)" "$SHA" "$*"; }
dval(){ grep -E "^$1=" "$DENV" | tail -1 | cut -d= -f2-; }

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -s /etc/bapc-vpn/.prod-db-password ] || { log "run setup-host.sh prod first"; exit 1; }
[ -s "$DENV" ] || { log "no Docker settings at $DENV"; exit 1; }
systemctl is-active -q "bapc-vpn@prod.target" && { log "the systemd prod instance is already running; nothing to cut over"; exit 1; }
HOST_URL="postgres://bapc_security:$(cat /etc/bapc-vpn/.prod-db-password)@127.0.0.1:5432/bapc_security_core"
[ "$(psql "$HOST_URL" -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='bapc_security_core'")" = 0 ] || { log "host database isn't empty; refusing to restore over it"; exit 1; }

log "1/8 fresh backup of the Docker database"
systemctl start bapc-vpn-backup.service

log "2/8 building the release (Docker keeps serving)"
BUILD_ONLY=1 bash "$HERE/release.sh" prod "$BUNDLE" "$SHA"

log "3/8 writing $ENV_FILE from the Docker settings"
umask 027
cp "$HERE/instance.env.example" "$ENV_FILE.new"
for k in CONTROL_API_TOKEN_SECRET EVENT_SIGNING_SECRET OOB_SHARED_SECRET DIAGNOSTICS_SHARED_SECRET HEADQUARTERS_SHARED_SECRET CLOUD_DEPLOYMENT_SHARED_SECRET INTEGRATION_SHARED_SECRET \
         ATTESTATION_PROVIDER RELAY_AGENT_TOKEN EGRESS_AGENT_TOKEN VPN_GATEWAY_PUBLIC_KEY VPN_GATEWAY_ENDPOINT VPN_CLIENT_DNS BAPC_CLIENT_SECRET BAPC_BILLING_KEY \
         BAPC_BILLING_HOOK_SECRET BAPC_NOTIFICATIONS_KEY WAREHOUSE_URL WAREHOUSE_SOURCE_ID WAREHOUSE_SIGNING_SECRET OBOP_INGEST_TOKEN OBOP_SYSTEM_ID PORTAL_PUBLIC_ORIGIN; do
  v=$(dval "$k" || true)
  [ -n "$v" ] && { esc=$(printf '%s' "$v" | sed 's/[&|\\]/\\&/g'); sed -i "s|^$k=.*|$k=$esc|" "$ENV_FILE.new"; }
done
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=$HOST_URL|; s|^BAPC_RELEASE=.*|BAPC_RELEASE=$SHA|" "$ENV_FILE.new"
chown root:bapc-vpn "$ENV_FILE.new"; chmod 640 "$ENV_FILE.new"; mv "$ENV_FILE.new" "$ENV_FILE"

counts(){ # $1 = "docker" or a database URL
  local q="SELECT (SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('bapc_security_core','public') AND table_type='BASE TABLE')||' '||(SELECT count(*) FROM public.schema_migrations)"
  for t in "${TABLES[@]}"; do q="$q||' '||(SELECT count(*) FROM bapc_security_core.$t)"; done
  if [ "$1" = docker ]; then (cd "$DOCKER_DIR" && docker compose exec -T postgres psql -U bapc_security -d bapc_security_core -tAc "$q"); else psql "$1" -tAc "$q"; fi
}

back_to_docker(){
  set +e
  log "PUTTING DOCKER BACK"
  systemctl stop "bapc-vpn@prod.target" 2>/dev/null; systemctl disable -q "bapc-vpn@prod.target" 2>/dev/null
  (cd "$DOCKER_DIR" && docker compose start postgres && docker compose start "${APP_SERVICES[@]}")
  sleep 15; curl -fsS http://127.0.0.1:8080/healthz >/dev/null && log "Docker is serving again" || log "Docker did NOT come back healthy: look now"
  exit 1
}
trap back_to_docker ERR

log "4/8 stopping the Docker app services (downtime starts)"
(cd "$DOCKER_DIR" && docker compose stop "${APP_SERVICES[@]}")
BEFORE=$(counts docker)

log "5/8 copying the database into host PostgreSQL 18"
install -d -m 700 /var/backups/bapc-vpn
(cd "$DOCKER_DIR" && docker compose exec -T postgres pg_dump -U bapc_security -d bapc_security_core --format=custom --no-owner --no-privileges) > "$DUMP"
pg_restore --dbname="$HOST_URL" --no-owner --no-privileges --exit-on-error "$DUMP"
AFTER=$(counts "$HOST_URL")
log "counts (tables migrations ${TABLES[*]}): docker [$BEFORE] host [$AFTER]"
[ "$BEFORE" = "$AFTER" ] || { log "counts differ"; false; }

log "6/8 starting the systemd services"
systemctl enable -q "bapc-vpn@prod.target"
systemctl start "bapc-vpn@prod.target"
sleep 8
for u in migrate api portal grpc oob worker dns console relay egress; do systemctl is-active -q "bapc-vpn-$u@prod.service" || { log "bapc-vpn-$u@prod not active"; journalctl -u "bapc-vpn-$u@prod" -n 15 --no-pager; false; }; done
for n in $(seq 1 10); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/ | grep -q '"bapc-vpn-security"' || { log "API check failed"; false; }
curl -fsS -o /dev/null http://127.0.0.1:8095/healthz || { log "portal check failed"; false; }
log "serving from systemd (downtime ended)"
trap - ERR

log "7/8 gateway sync and nightly backup follow the new settings and database"
install -d /etc/systemd/system/bapc-gateway-sync.service.d
printf '[Service]\nEnvironment=BAPC_ENV_FILE=%s\n' "$ENV_FILE" > /etc/systemd/system/bapc-gateway-sync.service.d/native.conf
install -d -m 700 /etc/bapc-vpn-backup
( umask 077; printf 'DATABASE_URL=%s\n' "$HOST_URL" > /etc/bapc-vpn-backup/env )
systemctl daemon-reload; systemctl restart bapc-gateway-sync
sleep 12; journalctl -u bapc-gateway-sync --since "-15 sec" --no-pager -o cat | grep -q sync_failed && log "WARNING: gateway sync reported a failure; check it" || log "gateway sync OK"
systemctl start bapc-vpn-backup.service && log "backup from the host database: OK" || log "WARNING: backup from the host database failed; check it"

log "8/8 stopping the Docker Postgres container (kept for rollback; not deleted)"
(cd "$DOCKER_DIR" && docker compose stop postgres)
log "done: prod runs on systemd + host PostgreSQL 18. The Docker copy is stopped, not removed (rollback: see deploy/native/README.md)."
