#!/usr/bin/env bash
# Prepares the bapc-vpn server to run BAPC VPN without Docker: Node 22 and PostgreSQL 18 from Ubuntu's own
# repositories, a locked-down system user, the systemd templates, and one instance's folders, database and settings.
# Safe to run again. Starts nothing: deploy/native/release.sh starts an instance, deploy/native/cutover.sh moves prod.
#
#   bash setup-host.sh staging   # a full staging copy: own database, own secrets, ports 18080/18095/...
#   bash setup-host.sh prod      # prod's folders and an empty database only; cutover.sh fills both from Docker
set -euo pipefail
INSTANCE=${1:?usage: setup-host.sh prod|staging}
case "$INSTANCE" in prod|staging) ;; *) echo "instance must be prod or staging" >&2; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
log(){ printf '%s setup-host %s: %s\n' "$(date -u +%FT%TZ)" "$INSTANCE" "$*"; }

log "packages (Ubuntu repositories only)"
need=()
command -v node >/dev/null || need+=(nodejs)
command -v npm >/dev/null || need+=(npm)
dpkg -s postgresql-18 >/dev/null 2>&1 || need+=(postgresql-18)
command -v openssl >/dev/null || need+=(openssl)
if [ ${#need[@]} -gt 0 ]; then apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"; fi
node -e 'const [maj]=process.versions.node.split(".").map(Number); if(maj<22){console.error("Node 22+ needed, have "+process.versions.node); process.exit(1)}'

log "PostgreSQL: loopback only, password (scram) logins"
PGCONF=$(ls -d /etc/postgresql/18/main)
grep -q "^listen_addresses = 'localhost'" "$PGCONF/postgresql.conf" || sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" "$PGCONF/postgresql.conf"
systemctl enable -q --now postgresql

log "system user and folders"
id bapc-vpn >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin bapc-vpn
install -d -m 755 /opt/bapc-vpn-native
install -d -m 755 -o root -g root "/opt/bapc-vpn-native/$INSTANCE" "/opt/bapc-vpn-native/$INSTANCE/releases"
install -d -m 750 -o root -g bapc-vpn /etc/bapc-vpn

log "systemd templates"
install -m 644 "$HERE"/systemd/*.service "$HERE"/systemd/*.target /etc/systemd/system/
systemctl daemon-reload

DB=bapc_security_core; ROLE=bapc_security
[ "$INSTANCE" = staging ] && { DB=bapc_security_staging; ROLE=bapc_security_staging; }
ENV_FILE="/etc/bapc-vpn/$INSTANCE.env"
db_exists=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB'")
role_exists=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$ROLE'")

if [ -z "$role_exists" ]; then
  PW=$(openssl rand -hex 24)
  # CREATEDB: the nightly backup restores into a throwaway database to prove the copy works.
  sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c "CREATE ROLE $ROLE LOGIN CREATEDB PASSWORD '$PW'"
  log "role $ROLE created"
else
  PW=""
fi
# Left empty on purpose: the migrations (or, for prod, the restored copy) create everything, pgcrypto included
# (a trusted extension, so the owning role may create it without superuser).
[ -z "$db_exists" ] && { sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $DB OWNER $ROLE"; log "database $DB created"; }

if [ "$INSTANCE" = staging ] && [ ! -s "$ENV_FILE" ]; then
  [ -n "$PW" ] || { echo "role $ROLE exists but $ENV_FILE doesn't: set DATABASE_URL by hand" >&2; exit 1; }
  r(){ openssl rand -hex 32; }
  umask 027
  sed -e "s|^DATABASE_URL=.*|DATABASE_URL=postgres://$ROLE:$PW@127.0.0.1:5432/$DB|" \
      -e "s|^\(CONTROL_API_TOKEN_SECRET\|EVENT_SIGNING_SECRET\|OOB_SHARED_SECRET\|DIAGNOSTICS_SHARED_SECRET\|HEADQUARTERS_SHARED_SECRET\|CLOUD_DEPLOYMENT_SHARED_SECRET\|INTEGRATION_SHARED_SECRET\)=$|&__R__|" \
      -e "s|^PORT=8080|PORT=18080|; s|^PORTAL_PORT=8095|PORTAL_PORT=18095|; s|^GRPC_PORT=50051|GRPC_PORT=60051|; s|^OOB_PORT=8181|OOB_PORT=18181|" \
      -e "s|^OOB_CONTROLLER_URL=.*|OOB_CONTROLLER_URL=http://127.0.0.1:18181|; s|^ADMIN_CONSOLE_PORT=8090|ADMIN_CONSOLE_PORT=18090|; s|^DNS_PORT=5353|DNS_PORT=15353|" \
      -e "s|^RELAY_PORT=51900|RELAY_PORT=61900|; s|^EGRESS_PORT=1080|EGRESS_PORT=11080|; s|^BAPC_CONTROLLER_URL=.*|BAPC_CONTROLLER_URL=http://127.0.0.1:18080|" \
      -e "s|^RELAY_PUBLIC_ENDPOINT=.*|RELAY_PUBLIC_ENDPOINT=127.0.0.1:61900|; s|^EGRESS_FIXED_IP=.*|EGRESS_FIXED_IP=127.0.0.1:11080|" \
      -e "s|^PORTAL_PUBLIC_ORIGIN=.*|PORTAL_PUBLIC_ORIGIN=https://staging-vpn.bapc.app|; s|^WAREHOUSE_URL=.*|WAREHOUSE_URL=|" \
      "$HERE/instance.env.example" > "$ENV_FILE.new"
  while grep -q "__R__" "$ENV_FILE.new"; do sed -i "0,/__R__/s//$(r)/" "$ENV_FILE.new"; done
  chown root:bapc-vpn "$ENV_FILE.new"; chmod 640 "$ENV_FILE.new"; mv "$ENV_FILE.new" "$ENV_FILE"
  log "wrote $ENV_FILE (own secrets; no gateway, Billing, email, Warehouse or Observability keys)"
fi
if [ "$INSTANCE" = prod ] && [ -n "$PW" ]; then
  umask 077; printf '%s\n' "$PW" > /etc/bapc-vpn/.prod-db-password; chmod 600 /etc/bapc-vpn/.prod-db-password
  log "prod role password kept in /etc/bapc-vpn/.prod-db-password for cutover.sh"
fi
log "done. Next: release.sh $INSTANCE <bundle> <sha>$([ "$INSTANCE" = prod ] && echo ' (via cutover.sh)')"
