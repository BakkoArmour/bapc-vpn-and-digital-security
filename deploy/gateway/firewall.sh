#!/bin/sh
# BAPC VPN gateway packet rules — run by bapc-gateway-firewall.service
# whenever wg0 comes up or goes down:  firewall.sh up|down <iface>
#
# What a joined device may do through the tunnel:
#   * go OUT to the internet via the server's public interface (NAT'd)
#   * receive replies to its own connections
# What it may NOT do:
#   * reach any service on this host (sshd, Docker-published ports, ...)
#   * reach Docker's internal bridge networks
#   * reach any other VPN customer (hub-and-spoke, no client-to-client)
#
# Rules live in our own chains and are jumped to from the TOP of FORWARD,
# DOCKER-USER (which Docker evaluates before its own and ufw's rules) and
# INPUT, so neither Docker's nor ufw's rule ordering can let tunnel traffic
# slip past them.
set -eu
ACTION="${1:-}"; IFACE="${2:-wg0}"
WAN="$(ip -4 route show default | awk '/default/ {print $5; exit}')"
[ -n "$WAN" ] || { echo "no IPv4 default route" >&2; exit 1; }
V4_NET="10.144.0.0/16"
V6_NET="fd14:4b41:5043::/64"
HAS_V6=0
ip -6 route show default | grep -q . && HAS_V6=1

unhook() { # cmd chain-from target
  while $1 -C "$2" -j "$3" 2>/dev/null; do $1 -D "$2" -j "$3"; done
}

teardown() {
  for cmd in iptables ip6tables; do
    unhook $cmd FORWARD BAPC-WG-FWD
    $cmd -n -L DOCKER-USER >/dev/null 2>&1 && unhook $cmd DOCKER-USER BAPC-WG-FWD
    unhook $cmd INPUT BAPC-WG-IN
    for chain in BAPC-WG-FWD BAPC-WG-IN; do
      $cmd -F "$chain" 2>/dev/null || true
      $cmd -X "$chain" 2>/dev/null || true
    done
  done
  iptables -t nat -D POSTROUTING -s "$V4_NET" -o "$WAN" -j MASQUERADE 2>/dev/null || true
  ip6tables -t nat -D POSTROUTING -s "$V6_NET" -o "$WAN" -j MASQUERADE 2>/dev/null || true
  for cmd in iptables ip6tables; do
    $cmd -t mangle -D FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    $cmd -t mangle -D FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  done
}

setup_family() { # cmd egress-allowed(0/1)
  cmd="$1"; egress="$2"
  $cmd -N BAPC-WG-FWD
  if [ "$egress" = 1 ]; then
    $cmd -A BAPC-WG-FWD -i "$IFACE" -o "$WAN" -j ACCEPT
    $cmd -A BAPC-WG-FWD -i "$WAN" -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  fi
  # REJECT (not DROP) so a client without IPv6 egress falls back to IPv4 at
  # once instead of timing out.
  $cmd -A BAPC-WG-FWD -i "$IFACE" -j REJECT
  $cmd -A BAPC-WG-FWD -o "$IFACE" -j DROP
  $cmd -I FORWARD 1 -j BAPC-WG-FWD
  $cmd -n -L DOCKER-USER >/dev/null 2>&1 && $cmd -I DOCKER-USER 1 -j BAPC-WG-FWD

  $cmd -N BAPC-WG-IN
  $cmd -A BAPC-WG-IN -i "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  if [ "$cmd" = iptables ]; then
    $cmd -A BAPC-WG-IN -i "$IFACE" -p icmp --icmp-type echo-request -j ACCEPT
  else
    $cmd -A BAPC-WG-IN -i "$IFACE" -p ipv6-icmp -j ACCEPT
  fi
  $cmd -A BAPC-WG-IN -i "$IFACE" -j DROP
  $cmd -I INPUT 1 -j BAPC-WG-IN

  $cmd -t mangle -A FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  $cmd -t mangle -A FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

case "$ACTION" in
  up)
    teardown
    setup_family iptables 1
    iptables -t nat -A POSTROUTING -s "$V4_NET" -o "$WAN" -j MASQUERADE
    setup_family ip6tables "$HAS_V6"
    [ "$HAS_V6" = 1 ] && ip6tables -t nat -A POSTROUTING -s "$V6_NET" -o "$WAN" -j MASQUERADE
    ;;
  down) teardown ;;
  *) echo "usage: $0 up|down <iface>" >&2; exit 2 ;;
esac
exit 0
