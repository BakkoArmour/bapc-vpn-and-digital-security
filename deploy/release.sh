#!/usr/bin/env bash
# One-step release of the BAPC VPN control plane on its server, with
# automatic rollback. Run as root on the server:
#   bash /opt/bapc-vpn-releases/<sha>/deploy/release.sh /opt/bapc-vpn-releases/<sha>.tar.gz <sha>
# Meant to be started detached (systemd-run --unit=bapc-vpn-release ...), so
# a dropped SSH connection can't interrupt it halfway; progress goes to the
# journal (journalctl -u bapc-vpn-release).
#
# Steps:
#   1. fresh verified database backup (bapc-vpn-backup; also sent offsite),
#   2. saves the running code as /opt/bapc-vpn-releases/before-<stamp>.tgz and
#      tags every running image deploy-*:latest as deploy-*:rollback-<stamp>,
#   3. unpacks the new code over /opt/bapc-vpn, keeping the server-only
#      deploy/.env and deploy/docker-compose.override.yml,
#   4. builds the images and starts the stack (the one-shot migrate job runs
#      first; nothing else starts unless it succeeds),
#   5. checks: migrate exited 0, every long-running service is up,
#      control-api (/healthz and /) and the customer portal answer (control-api
#      only reports ready after it has connected to the database),
#   6. any failure in 3-5 rolls back automatically: restores the saved code,
#      retags the saved images as :latest and restarts them (no rebuild).
# Rollback by hand later: bash deploy/rollback.sh <stamp> (see that file).
set -Eeuo pipefail
BUNDLE=${1:?path to the release .tar.gz}
SHA=${2:?commit sha of the release}
APP=/opt/bapc-vpn
REL=/opt/bapc-vpn-releases
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
cd "$APP/deploy"

log(){ printf '%s release %s: %s\n' "$(date -u +%FT%TZ)" "$SHA" "$*"; }
compose(){ docker compose "$@"; }
images(){ docker images --format '{{.Repository}}' | grep -E '^deploy-' | sort -u; }

log "1/5 fresh backup before the release"
systemctl start bapc-vpn-backup.service || { log "backup failed; nothing changed, stopping"; exit 1; }

log "2/5 saving the running release for rollback ($STAMP)"
install -d -m 700 "$REL"
tar -czf "$REL/before-$STAMP.tgz" -C /opt bapc-vpn
for i in $(images); do docker tag "$i:latest" "$i:rollback-$STAMP"; done
echo "$STAMP" > "$REL/last-rollback-point"

rollback(){
  log "ROLLING BACK to the release saved at $STAMP"
  set +e
  rm -rf "$APP.failed" && mv "$APP" "$APP.failed"
  tar -xzf "$REL/before-$STAMP.tgz" -C /opt
  cp -p "$APP.failed/deploy/.env" "$APP/deploy/.env"   # secrets may have been edited since; keep the newest
  for i in $(images); do docker image inspect "$i:rollback-$STAMP" >/dev/null 2>&1 && docker tag "$i:rollback-$STAMP" "$i:latest"; done
  cd "$APP/deploy" && compose up -d --no-build
  log "rolled back; the failed tree is kept at $APP.failed for inspection"
  exit 1
}
trap rollback ERR

log "3/5 unpacking $SHA"
TMP=$(mktemp -d "$REL/unpack-XXXX")
tar -xzf "$BUNDLE" -C "$TMP" --strip-components=1
[ -f "$TMP/deploy/docker-compose.yml" ] || { log "bundle has no deploy/docker-compose.yml"; false; }
# Never ship server-only files from a bundle, even if one slipped in.
rm -f "$TMP/deploy/.env" "$TMP/deploy/docker-compose.override.yml"
cp -a "$TMP/." "$APP/"
rm -rf "$TMP"
echo "$SHA $STAMP" > "$APP/RELEASE"

log "4/5 building and starting"
compose build --pull=false 2>&1 | tail -5
compose up -d 2>&1 | tail -20

log "5/5 checking"
for n in $(seq 1 30); do
  bad=$(compose ps --format '{{.Service}} {{.State}} {{.Health}}' | awk '$1!="migrate" && ($2!="running" || $3=="unhealthy" || $3=="starting")' | wc -l)
  [ "$bad" = 0 ] && break; sleep 5
done
compose ps --format '{{.Service}}\t{{.State}}\t{{.Status}}'
[ "$bad" = 0 ] || { log "services not healthy after 150s"; false; }
[ "$(docker inspect -f '{{.State.ExitCode}}' deploy-migrate-1)" = 0 ] || { log "migrate job failed"; compose logs --tail 20 migrate; false; }
curl -fsS http://127.0.0.1:8080/healthz >/dev/null || { log "control-api /healthz failed"; false; }
curl -fsS -o /dev/null http://127.0.0.1:8095/ || { log "customer portal failed"; false; }
curl -fsS http://127.0.0.1:8080/ | grep -q '"bapc-vpn-security"' || { log "control-api / did not identify itself"; false; }
trap - ERR
log "released $SHA; rollback point $STAMP (bash $APP/deploy/rollback.sh $STAMP)"
