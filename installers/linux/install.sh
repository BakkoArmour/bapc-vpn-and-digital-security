#!/usr/bin/env bash
# BAPC endpoint agent installer (Linux/systemd).
# Usage: sudo ./install.sh [/path/to/built/repo]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must be run as root (sudo ./install.sh)" >&2
  exit 1
fi

SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
INSTALL_DIR="/opt/bapc-security"
CONFIG_DIR="/etc/bapc-security"
STATE_DIR="/var/lib/bapc-security"
UNIT_PATH="/etc/systemd/system/bapc-security-agent.service"

if [[ ! -d "${SOURCE_DIR}/dist" ]]; then
  echo "no dist/ found in ${SOURCE_DIR} — run 'npm run build' before installing" >&2
  exit 1
fi

id -u bapc-security &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin bapc-security

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}"
cp -r "${SOURCE_DIR}/dist" "${SOURCE_DIR}/node_modules" "${SOURCE_DIR}/package.json" "${INSTALL_DIR}/"
chown -R bapc-security:bapc-security "${INSTALL_DIR}" "${STATE_DIR}"
chmod 750 "${STATE_DIR}"

if [[ ! -f "${CONFIG_DIR}/agent.env" ]]; then
  cat > "${CONFIG_DIR}/agent.env" <<'EOF'
# BAPC endpoint agent configuration. See docs/PRODUCTION-ADAPTERS.md.
NODE_ENV=production
# CONTROLLER_URL=https://security-control.internal
# AGENT_VERSION=0.4.0
EOF
  chmod 640 "${CONFIG_DIR}/agent.env"
  chown root:bapc-security "${CONFIG_DIR}/agent.env"
fi

cp "$(dirname "${BASH_SOURCE[0]}")/bapc-security-agent.service" "${UNIT_PATH}"
systemctl daemon-reload
systemctl enable --now bapc-security-agent.service

echo "Installed. Check status with: systemctl status bapc-security-agent" >&2
