#!/usr/bin/env python3
"""BAPC VPN gateway peer sync.

Keeps wg0's peer list equal to what the control plane says it should be
(GET /api/v1/gateway/peers): every joined, non-revoked, non-compromised
device, each allowed ONLY its own tunnel address. Runs as a systemd service
on the gateway host (bapc-gateway-sync.service), polling control-api over
loopback — control-api is published on 127.0.0.1 only, never publicly.

The bearer token is minted locally on every pass from
CONTROL_API_TOKEN_SECRET in the deploy .env (the same HMAC format
HmacBearerGuard accepts, src/api/rest/guard.ts), valid for 5 minutes, role
security-agent only — so no long-lived token sits on disk.

If the control plane is unreachable the current peers are left as they are
(fail static) and the error is logged; nothing is ever applied from a
response that doesn't validate.
"""
import base64, hashlib, hmac, ipaddress, json, os, re, subprocess, sys, tempfile, time, urllib.request

IFACE = os.environ.get("BAPC_WG_IFACE", "wg0")
API = os.environ.get("BAPC_CONTROL_API", "http://127.0.0.1:8080")
ENV_FILE = os.environ.get("BAPC_ENV_FILE", "/opt/bapc-vpn/deploy/.env")
INTERVAL = int(os.environ.get("BAPC_SYNC_INTERVAL", "10"))
FIREWALL = os.environ.get("BAPC_FIREWALL_SCRIPT", "/usr/local/lib/bapc-gateway/firewall.sh")
V4_NET = ipaddress.ip_network("10.144.0.0/16")
V6_NET = ipaddress.ip_network("fd14:4b41:5043::/64")
WG_KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
SUB = "6a7e0000-0000-4000-8000-000000000001"  # fixed identity for audit trails


def log(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def read_secret():
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            key, sep, value = line.strip().partition("=")
            if sep and key == "CONTROL_API_TOKEN_SECRET":
                return value.strip().strip('"').strip("'")
    raise RuntimeError(f"CONTROL_API_TOKEN_SECRET not found in {ENV_FILE}")


def mint_token(secret):
    claims = {"sub": SUB, "roles": ["security-agent"], "exp": int(time.time()) + 300}
    encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    sig = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def fetch_peers(secret):
    req = urllib.request.Request(f"{API}/api/v1/gateway/peers", headers={"authorization": f"Bearer {mint_token(secret)}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)["data"]


def validated(peers):
    """Only ever a single-host route inside the VPN's own ranges per peer, so
    a bad or tampered response can never route someone else's traffic (or
    0.0.0.0/0) to a client."""
    out = {}
    for p in peers:
        key = p.get("publicKey", "")
        if not WG_KEY.match(key):
            raise ValueError(f"invalid peer key {key!r}")
        ips = []
        for cidr in p.get("allowedIps", []):
            net = ipaddress.ip_network(cidr, strict=True)
            inside = (net.version == 4 and net.subnet_of(V4_NET) and net.prefixlen == 32) or \
                     (net.version == 6 and net.subnet_of(V6_NET) and net.prefixlen == 128)
            if not inside:
                raise ValueError(f"refusing allowed-ip {cidr} for peer {key}")
            ips.append(str(net))
        if ips:
            out[key] = sorted(ips)
    return out


def firewall_present():
    return subprocess.run(["iptables", "-C", "FORWARD", "-j", "BAPC-WG-FWD"], capture_output=True).returncode == 0


def apply(peers):
    base = subprocess.run(["wg-quick", "strip", IFACE], check=True, capture_output=True, text=True).stdout
    lines = [base.rstrip(), ""]
    for key, ips in sorted(peers.items()):
        lines += ["[Peer]", f"PublicKey = {key}", f"AllowedIPs = {', '.join(ips)}", ""]
    with tempfile.NamedTemporaryFile("w", dir="/run", prefix="bapc-wg-", delete=False) as f:
        os.chmod(f.name, 0o600)
        f.write("\n".join(lines))
        path = f.name
    try:
        subprocess.run(["wg", "syncconf", IFACE, path], check=True, capture_output=True, text=True)
    finally:
        os.unlink(path)


def main():
    applied = None
    while True:
        try:
            if not firewall_present():
                subprocess.run([FIREWALL, "up", IFACE], check=True, capture_output=True, text=True)
                log("gateway.firewall_restored")
            peers = validated(fetch_peers(read_secret()))
            digest = hashlib.sha256(json.dumps(peers, sort_keys=True).encode()).hexdigest()
            if digest != applied:
                apply(peers)
                applied = digest
                log("gateway.peers_applied", count=len(peers))
        except Exception as e:  # keep running; current peers stay as they are
            log("gateway.sync_failed", error=str(e))
        time.sleep(INTERVAL)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        apply(validated(fetch_peers(read_secret())))
    else:
        main()
