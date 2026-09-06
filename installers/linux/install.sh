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
# Run `npm run enroll` (as root, from this repo) before starting the
# service — it generates this node's WireGuard/identity keys, registers
# with the control plane, brings the interface up, and writes BAPC_NODE_ID
# below automatically.
NODE_ENV=production
# BAPC_CONTROLLER_URL=https://security-control.internal
# Both of these are needed only for ROTATE_IDENTITY_REQUIRED (a threat-
# triggered identity rotation the node performs itself — see
# agents/shared/production-agent.ts). Everything else works without them.
# BAPC_CONTROLLER_GRPC_URL=security-control.internal:50051
# BAPC_IDENTITY_KEY_PATH=/etc/bapc-security/identity-key.pem
# BAPC_AGENT_VERSION=0.4.0
# BAPC_AGENT_TOKEN=... (issued out of band — enrollment does not mint this)
EOF
  chmod 640 "${CONFIG_DIR}/agent.env"
  chown root:bapc-security "${CONFIG_DIR}/agent.env"
fi

cp "$(dirname "${BASH_SOURCE[0]}")/bapc-security-agent.service" "${UNIT_PATH}"
systemctl daemon-reload

echo "Installed. Before starting the service: run 'npm run enroll' from ${SOURCE_DIR} as root," >&2
echo "then set BAPC_CONTROLLER_URL and BAPC_AGENT_TOKEN in ${CONFIG_DIR}/agent.env." >&2
echo "Then: systemctl enable --now bapc-security-agent" >&2
