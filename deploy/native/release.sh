#!/usr/bin/env bash
# One-step release of BAPC VPN on the systemd (no Docker) layout, with automatic rollback. Run as root on the server,
# ideally detached so a dropped SSH connection can't stop it halfway:
#   systemd-run --unit=bapc-vpn-release-<instance> bash release.sh <instance> /opt/bapc-vpn-releases/bapc-vpn-<sha>.tar.gz <sha>
#
# 1. prod only: a fresh verified database backup (bapc-vpn-backup),
# 2. unpacks the bundle into /opt/bapc-vpn-native/<instance>/releases/<sha>, installs exactly package-lock.json, builds,
#    drops dev dependencies,
# 3. points /opt/bapc-vpn-native/<instance>/current at it (the previous target is kept as the rollback point),
# 4. runs the migrations unit, then restarts every service of the instance,
# 5. checks: every unit active, the API's /healthz and the portal answer on the instance's ports,
# 6. on any failure: points current back at the previous release and restarts it (the database is forward-only).
# Keeps the 5 newest releases.
set -Eeuo pipefail
INSTANCE=${1:?usage: release.sh prod|staging <bundle.tar.gz> <sha>}
BUNDLE=${2:?bundle}
SHA=${3:?sha}
case "$INSTANCE" in prod|staging) ;; *) echo "instance must be prod or staging" >&2; exit 2;; esac
BASE=/opt/bapc-vpn-native/$INSTANCE
ENV_FILE=/etc/bapc-vpn/$INSTANCE.env
UNITS=(api portal grpc oob worker dns console relay egress)
log(){ printf '%s release %s %s: %s\n' "$(date -u +%FT%TZ)" "$INSTANCE" "$SHA" "$*"; }
envval(){ grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }

[ -s "$ENV_FILE" ] || { log "no $ENV_FILE: run setup-host.sh (and cutover.sh for prod) first"; exit 1; }
[ -d "$BASE/releases" ] || { log "no $BASE: run setup-host.sh first"; exit 1; }

if [ "$INSTANCE" = prod ] && systemctl cat bapc-vpn-backup.service >/dev/null 2>&1; then
  log "1/5 fresh backup"
  systemctl start bapc-vpn-backup.service || { log "backup failed; nothing changed"; exit 1; }
fi

log "2/5 unpacking and building"
DEST=$BASE/releases/$SHA
rm -rf "$DEST.tmp" && mkdir -p "$DEST.tmp"
tar -xzf "$BUNDLE" -C "$DEST.tmp" --strip-components=1
rm -f "$DEST.tmp/deploy/.env"   # never ship settings in a bundle
( cd "$DEST.tmp" && npm ci --no-audit --no-fund --loglevel=error && npm run -s build && npm prune --omit=dev --no-audit --no-fund --loglevel=error )
echo "$SHA $(date -u +%Y%m%dT%H%M%SZ)" > "$DEST.tmp/RELEASE"
chown -R root:root "$DEST.tmp"; chmod -R go-w "$DEST.tmp"
rm -rf "$DEST" && mv "$DEST.tmp" "$DEST"

PREV=$(readlink -f "$BASE/current" 2>/dev/null || true)
restart_all(){
  # Every unit is PartOf the target, so restarting it restarts them all; each service Requires and comes After the
  # migrations unit, so a database that fails to migrate leaves the services stopped instead of half-started.
  systemctl daemon-reload
  systemctl restart "bapc-vpn@$INSTANCE.target"
}
rollback(){
  set +e
  if [ -n "$PREV" ] && [ -d "$PREV" ]; then
    log "ROLLING BACK to $(basename "$PREV")"
    ln -sfn "$PREV" "$BASE/current"; restart_all
    log "rolled back; $SHA stays in releases/ for inspection"
  else
    log "FAILED and there is no previous release to go back to; services stopped"
    systemctl stop "bapc-vpn@$INSTANCE.target"
  fi
  exit 1
}
trap rollback ERR

log "3/5 switching current -> $SHA (previous: ${PREV:+$(basename "$PREV")}${PREV:-none})"
ln -sfn "$DEST" "$BASE/current"
# cutover.sh builds prod's first release while Docker still serves, then starts it itself.
if [ "${BUILD_ONLY:-}" = 1 ]; then trap - ERR; log "built only (BUILD_ONLY=1); nothing restarted"; exit 0; fi

log "4/5 migrations, then every service"
systemctl enable -q "bapc-vpn@$INSTANCE.target"
restart_all

log "5/5 checking"
sleep 8
for u in migrate "${UNITS[@]}"; do systemctl is-active -q "bapc-vpn-$u@$INSTANCE.service" || { log "bapc-vpn-$u@$INSTANCE is not active"; journalctl -u "bapc-vpn-$u@$INSTANCE" -n 15 --no-pager; false; }; done
API=$(envval PORT); PORTAL=$(envval PORTAL_PORT)
for n in $(seq 1 10); do curl -fsS "http://127.0.0.1:$API/healthz" >/dev/null && break; sleep 2; done
curl -fsS "http://127.0.0.1:$API/healthz" >/dev/null || { log "API /healthz failed on $API"; false; }
curl -fsS "http://127.0.0.1:$API/" | grep -q '"bapc-vpn-security"' || { log "API / did not identify itself"; false; }
curl -fsS -o /dev/null "http://127.0.0.1:$PORTAL/healthz" || { log "portal failed on $PORTAL"; false; }
trap - ERR

ls -1dt "$BASE"/releases/*/ 2>/dev/null | tail -n +6 | while read -r old; do [ "$(readlink -f "$BASE/current")/" = "$old" ] || rm -rf "$old"; done
log "released $SHA on $INSTANCE (rollback: ln -sfn ${PREV:-<none>} $BASE/current && systemctl restart bapc-vpn@$INSTANCE.target)"
