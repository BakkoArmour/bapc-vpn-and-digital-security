# Device join and the VPN gateway

How a customer device gets onto BAPC VPN, end to end.

## Pieces

| Piece | Where | What it does |
|---|---|---|
| Invite | `enrollment_invites` (db/020) | One-time code minted by the owner. Only its SHA-256 is stored. Single use, expires (default 24h, max 14 days). |
| Join route | `POST /api/v1/devices/join` on control-api | Public HTTPS (through the Cloudflare tunnel). Needs a valid invite **and** passing hardware attestation. Answers with the device's tunnel address and the gateway peer. |
| Attestation | `ATTESTATION_PROVIDER=windows-tpm` | The device signs an envelope with a key created inside its TPM, bound to its CSR's identity key. Verified by `WindowsTpmAttestationProvider`. The allow-all development provider stays refused in production. |
| Gateway | `deploy/gateway/` on the control-plane host | WireGuard `wg0` (10.144.0.1/16, fd14:4b41:5043::1/64) on UDP 51820. NATs device traffic out to the internet. Devices can't reach the host's services, Docker networks, or each other. |
| Peer sync | `bapc-gateway-sync.service` | Every 10s, pulls `GET /api/v1/gateway/peers` over loopback and applies it to `wg0`. Revoked or compromised devices drop off on the next pass. |
| Windows client | `installers/windows/join-vpn.ps1` | Installs WireGuard (signature-checked), creates TPM keys, joins, installs the `BAPC` tunnel, checks traffic exits through the gateway, and switches it off again if not. |

Topology is hub-and-spoke: a device's only peer is the gateway, with a
full-tunnel route (`0.0.0.0/0, ::/0`). gRPC `registerNode` (mesh-grpc) is
unchanged. It has no caller authentication, so it stays bound to
127.0.0.1 and is never exposed.

## Setting up the gateway (once, as root on the server)

```sh
sh /opt/bapc-vpn/deploy/gateway/setup-gateway.sh
cd /opt/bapc-vpn/deploy && docker compose up -d control-api
```

This opens exactly one public port, UDP 51820, in ufw. WireGuard runs on the
host rather than in Docker, so ufw governs it. Docker-published ports bypass
ufw, which is why every one of them stays bound to 127.0.0.1.

## Inviting a device

On the server:

```sh
cd /opt/bapc-vpn/deploy
docker compose exec control-api node dist/src/runtime/mint-invite.js --hours 24 --label "Owner laptop"
```

Or over HTTPS with a `security-owner` token: `POST /api/v1/devices/invites {"hours":24,"label":"..."}`.

## Joining a Windows PC

In PowerShell opened with "Run as administrator":

```powershell
powershell -ExecutionPolicy Bypass -File .\installers\windows\join-vpn.ps1 -InviteCode BAPC-XXXXXX-XXXXXX-XXXXXX-XXXXXX
```

Run it again to reconnect. To switch the VPN off, add `-Disconnect`.

## Known limits

- **TPM evidence.** The server checks the envelope's signature. It doesn't yet
  validate the attestation key's Endorsement Key chain or compare the
  measured-boot digest against a baseline (see `providers.ts`). The invite is
  the real gate on *who* can join.
- **Platforms.** Only one `ATTESTATION_PROVIDER` is active per deployment.
  With `windows-tpm`, only Windows devices can join today.
- **Fail-static sync.** If control-api is down, the gateway keeps its last
  peer list. A revocation then takes effect once control-api is back.
