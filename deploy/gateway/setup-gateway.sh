#!/bin/sh
# Turns the control-plane host into the BAPC VPN's WireGuard exit.
# Run as root from the deployed app's deploy/gateway directory:
#   sh /opt/bapc-vpn/deploy/gateway/setup-gateway.sh [public-ip]
#
# Idempotent: re-running keeps the existing gateway key (every joined device
# is pinned to it) and only refreshes scripts/config around it.
#
# Exposes exactly ONE new public port: UDP 51820 (WireGuard), opened in ufw.
# WireGuard runs on the host (not in Docker), so ufw governs it directly —
# unlike Docker-published ports, which bypass ufw and therefore stay bound
# to 127.0.0.1 in docker-compose.override.yml.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(dirname "$HERE")"
ENV_FILE="$DEPLOY_DIR/.env"
LIB=/usr/local/lib/bapc-gateway
PORT=51820
IFACE=wg0

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

WAN="$(ip -4 route show default | awk '/default/ {print $5; exit}')"
PUBLIC_IP="${1:-$(ip -4 -o addr show dev "$WAN" scope global | awk '{split($4,a,"/"); print a[1]; exit}')}"
[ -n "$PUBLIC_IP" ] || { echo "could not detect the public IPv4; pass it as the first argument" >&2; exit 1; }

install -d -m 755 "$LIB"
install -m 755 "$HERE/firewall.sh" "$LIB/firewall.sh"
install -m 755 "$HERE/gateway-sync.py" "$LIB/gateway-sync.py"

install -d -m 700 /etc/wireguard
if [ ! -s /etc/wireguard/$IFACE.key ]; then
  (umask 077 && wg genkey > /etc/wireguard/$IFACE.key)
fi
PUBKEY="$(wg pubkey < /etc/wireguard/$IFACE.key)"

(umask 077 && cat > /etc/wireguard/$IFACE.conf <<EOF
# Managed by bapc setup-gateway.sh — peers are added/removed live by
# bapc-gateway-sync.service from the control plane; don't add them here.
[Interface]
Address = 10.144.0.1/16, fd14:4b41:5043::1/64
ListenPort = $PORT
PrivateKey = $(cat /etc/wireguard/$IFACE.key)
PostUp = $LIB/firewall.sh up %i
PostDown = $LIB/firewall.sh down %i
EOF
)

{
  echo "net.ipv4.ip_forward = 1"
  if ip -6 route show default | grep -q .; then
    # Forwarding turns off router-advertisement acceptance unless accept_ra=2.
    echo "net.ipv6.conf.all.forwarding = 1"
    echo "net.ipv6.conf.$WAN.accept_ra = 2"
  fi
} > /etc/sysctl.d/99-bapc-gateway.conf
sysctl -q -p /etc/sysctl.d/99-bapc-gateway.conf

ufw allow $PORT/udp comment 'BAPC VPN WireGuard' >/dev/null

install -m 644 "$HERE/bapc-gateway-sync.service" /etc/systemd/system/bapc-gateway-sync.service
systemctl daemon-reload
systemctl enable -q wg-quick@$IFACE
systemctl restart wg-quick@$IFACE
systemctl enable -q bapc-gateway-sync
systemctl restart bapc-gateway-sync

# Tell control-api where joining devices should point (read by loadConfig's
# VPN_GATEWAY_* — see src/config.ts). Takes effect on control-api's next
# (re)start.
upsert() {
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"; fi
}
upsert VPN_GATEWAY_PUBLIC_KEY "$PUBKEY"
upsert VPN_GATEWAY_ENDPOINT "$PUBLIC_IP:$PORT"

echo "gateway ready: $PUBLIC_IP:$PORT/udp, public key $PUBKEY"
echo "now restart control-api so it picks up VPN_GATEWAY_*: (cd $DEPLOY_DIR && docker compose up -d control-api)"
