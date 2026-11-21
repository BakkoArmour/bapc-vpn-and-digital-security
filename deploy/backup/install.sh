#!/bin/sh
# Installs the nightly verified backup on the VPN server. Run as root from the
# deployed app's deploy/backup folder, with the encryption key on stdin
# (never printed; keep the same key in the BAPC vault so copies stay readable):
#   ssh root@<vpn-server> 'sh /opt/bapc-vpn/deploy/backup/install.sh' < bapc-vpn-backup-encryption-key.txt
# Re-running keeps an existing key unless a new one is piped in.
# The offsite token (BAPC Backup's SERVER_BACKUP_TOKEN) goes in
# /etc/bapc-vpn-backup/token, root only, the same way.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

install -d -m 700 /etc/bapc-vpn-backup /var/backups/bapc-vpn
if [ ! -t 0 ]; then
  KEY="$(cat)"
  if [ -n "$KEY" ]; then
    (umask 077 && printf '%s' "$KEY" > /etc/bapc-vpn-backup/key.new && mv /etc/bapc-vpn-backup/key.new /etc/bapc-vpn-backup/key)
  fi
fi
[ -s /etc/bapc-vpn-backup/key ] || { echo "no key: pipe the backup encryption key into this script" >&2; exit 1; }

install -m 755 "$HERE/bapc-vpn-backup.sh" /usr/local/bin/bapc-vpn-backup
install -m 644 "$HERE/bapc-vpn-backup.service" /etc/systemd/system/bapc-vpn-backup.service
install -m 644 "$HERE/bapc-vpn-backup.timer" /etc/systemd/system/bapc-vpn-backup.timer
systemctl daemon-reload
systemctl enable --now bapc-vpn-backup.timer
systemctl list-timers bapc-vpn-backup.timer --no-pager | head -3
