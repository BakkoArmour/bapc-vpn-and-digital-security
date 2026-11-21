#!/usr/bin/env bash
# Puts back a release saved by deploy/release.sh. Run as root on the server:
#   bash /opt/bapc-vpn/deploy/rollback.sh            # the most recent rollback point
#   bash /opt/bapc-vpn/deploy/rollback.sh <stamp>    # a specific one (ls /opt/bapc-vpn-releases)
# Restores the saved code tree and retags the saved images as :latest, then
# restarts without rebuilding. deploy/.env is kept from the current tree, so
# secrets set after the release aren't lost. The database is NOT rolled back
# (migrations are forward-only); restore a backup with scripts/db-restore.sh
# only if a release's migration has to be undone.
set -euo pipefail
REL=/opt/bapc-vpn-releases
APP=/opt/bapc-vpn
STAMP=${1:-$(cat "$REL/last-rollback-point")}
[ -f "$REL/before-$STAMP.tgz" ] || { echo "no saved release before-$STAMP.tgz in $REL" >&2; exit 1; }
cp -p "$APP/deploy/.env" "$REL/env-at-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
rm -rf "$APP.replaced" && mv "$APP" "$APP.replaced"
tar -xzf "$REL/before-$STAMP.tgz" -C /opt
cp -p "$APP.replaced/deploy/.env" "$APP/deploy/.env"
for i in $(docker images --format '{{.Repository}}' | grep -E '^deploy-' | sort -u); do
  docker image inspect "$i:rollback-$STAMP" >/dev/null 2>&1 && docker tag "$i:rollback-$STAMP" "$i:latest"
done
cd "$APP/deploy" && docker compose up -d --no-build
docker compose ps --format '{{.Service}}\t{{.State}}\t{{.Status}}'
echo "rolled back to the release saved at $STAMP; the replaced tree is at $APP.replaced"
