#!/usr/bin/env bash
# BAPC endpoint agent uninstaller (Linux/systemd). Leaves /etc/bapc-security
# config and /var/lib/bapc-security state in place unless --purge is given,
# so a reinstall doesn't lose local agent state by accident.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must be run as root (sudo ./uninstall.sh [--purge])" >&2
  exit 1
fi

systemctl disable --now bapc-security-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/bapc-security-agent.service
systemctl daemon-reload

rm -rf /opt/bapc-security

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /etc/bapc-security /var/lib/bapc-security
  userdel bapc-security 2>/dev/null || true
  echo "Purged configuration and state." >&2
else
  echo "Uninstalled. Configuration in /etc/bapc-security and state in /var/lib/bapc-security were kept (use --purge to remove)." >&2
fi
