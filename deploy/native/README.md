# BAPC VPN without Docker (systemd + host PostgreSQL 18)

Bryan doesn't use Docker any more. This folder moves BAPC VPN off Docker Compose on the `bapc-vpn` server
(116.203.78.222) onto plain systemd services and the host's PostgreSQL 18, from Ubuntu 26.04's own repositories
(Node 22.22, PostgreSQL 18.6; no third-party package sources). **Prepared, not applied**: each step below needs Bryan's yes.

## Layout

| | prod | staging |
|---|---|---|
| Code | `/opt/bapc-vpn-native/prod/current` → `releases/<sha>` | `/opt/bapc-vpn-native/staging/current` |
| Settings and secrets | `/etc/bapc-vpn/prod.env` (root:bapc-vpn 0640) | `/etc/bapc-vpn/staging.env` (own secrets) |
| Database (host PG 18, loopback) | `bapc_security_core`, role `bapc_security` | `bapc_security_staging`, role `bapc_security_staging` |
| Ports (all 127.0.0.1) | API 8080, portal 8095, gRPC 50051, OOB 8181, console 8090, DNS 5353, relay 51900, egress 1080 | 18080, 18095, 60051, 18181, 18090, 15353, 61900, 11080 |
| Public address | vpn.bapc.app, vpn.bapc-headquarters.com (tunnel, unchanged) | staging-vpn.bapc.app (needs a tunnel ingress + DNS) |
| VPN gateway (WireGuard wg0) | yes (host, unchanged) | no |
| Billing / email / Warehouse / Observability keys | yes | none (sign-in and payments say "coming soon") |

One set of systemd templates (`systemd/`) serves both: `bapc-vpn-<service>@<instance>.service`, grouped by
`bapc-vpn@<instance>.target`. Every service runs as the unprivileged `bapc-vpn` user with a read-only system, no
capabilities, private /tmp and a 512 MB memory cap (`systemd-analyze security`: 3.0, "OK"), and `Requires=` the
migrations unit, so nothing starts on a database that failed to migrate.

## Order of work (each needs Bryan's yes)

1. **Staging (the rehearsal).** `bash setup-host.sh staging`, then a release:
   `systemd-run --unit=bapc-vpn-release-staging bash release.sh staging /opt/bapc-vpn-releases/bapc-vpn-<sha>.tar.gz <sha>`.
   Add `staging-vpn.bapc.app → http://127.0.0.1:18095` to `/etc/cloudflared/config.yml` and a `staging-vpn` CNAME to the tunnel.
   Prove: the migrations, every unit, the release script's rollback (ship a deliberately broken bundle and watch it go back).
2. **Production move** (a short window; WireGuard tunnels keep working, only sign-in/device changes/payment updates pause):
   `bash setup-host.sh prod`, then `systemd-run --unit=bapc-vpn-cutover bash cutover.sh <bundle> <sha>` and follow it
   with `journalctl -u bapc-vpn-cutover -f`. See the script header for its 8 steps. Any failure puts Docker back by itself.
3. **After a week on systemd**, with Bryan's yes: remove the stopped Docker containers, images and volume, and Docker itself.

## Releasing after the move

`systemd-run --unit=bapc-vpn-release bash /opt/bapc-vpn-native/prod/current/deploy/native/release.sh prod <bundle> <sha>`
(backup → build into `releases/<sha>` → switch `current` → migrations → restart → checks → automatic rollback).
The Docker `deploy/release.sh` stays for as long as Docker serves.

## Rolling back

- **A bad release:** automatic. By hand: `ln -sfn /opt/bapc-vpn-native/prod/releases/<previous> /opt/bapc-vpn-native/prod/current && systemctl restart bapc-vpn@prod.target`.
- **Back to Docker after the cutover** (only in the first days; changes made since are lost unless copied):
  `systemctl stop bapc-vpn@prod.target && systemctl disable bapc-vpn@prod.target`, restore the latest host-database dump into
  the Docker Postgres (`docker compose start postgres`, then `pg_restore --clean`), `docker compose start` the app services,
  remove `/etc/systemd/system/bapc-gateway-sync.service.d/native.conf` and `/etc/bapc-vpn-backup/env`, `systemctl daemon-reload`,
  restart `bapc-gateway-sync`.

## Why not Cheisgos (yet)

BAPC Cheisgos (#36, sql.bapc.app) is live as a control plane but manages no database servers yet (0 agents enrolled), and its
agent runs PostgreSQL in Podman containers. The host PostgreSQL 18 here can be registered with BAPC Database (#07) and adopted
by Cheisgos once it manages servers; the VPN's control plane then doesn't depend on another machine to keep its gateway in sync.
