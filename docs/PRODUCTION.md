# BAPC VPN in production

How the live BAPC VPN runs, ships, is backed up, watched and supported. Current as of 21 Nov 2026 (release on
branch `vpn/launch-readiness`). The older [OPERATIONS-MANUAL.md](OPERATIONS-MANUAL.md) still describes each service and
the operator API; where the two differ, this file is the live truth.

## Where it runs

| Piece | Where |
|---|---|
| Server | `bapc-vpn`, Hetzner, 116.203.78.222 (IPv6 2a01:4f8:1c1a:1f97::1), Ubuntu 26.04. Code in `/opt/bapc-vpn`, settings and secrets in `/opt/bapc-vpn/deploy/.env` (root only). |
| Services | Docker Compose in `/opt/bapc-vpn/deploy` (`docker-compose.yml` + server-only `docker-compose.override.yml`, which binds every port to 127.0.0.1). Postgres 17 runs in the same stack (volume `security-db`). |
| VPN gateway | WireGuard `wg0` on the host, UDP 51820 (the only public port besides SSH). `bapc-gateway-sync` pulls the allowed device list every 10 s; `bapc-gateway-firewall` keeps devices off the host and each other. See [DEVICE-JOIN.md](DEVICE-JOIN.md). |
| Public addresses | Cloudflare tunnel `bapc-vpn-and-digital-security` (917ce328…): `vpn.bapc.app` → customer portal (127.0.0.1:8095), `vpn.bapc-headquarters.com` → control API (127.0.0.1:8080). DNS: `vpn` CNAME in bapc.app and bapc-headquarters.com, proxied. |
| Code | Code Adytum `bapc/bapc-vpn-and-digital-security` (main copy) and GitHub (backup). |

## Shipping a release (one step, with automatic rollback)

From a clean checkout of the commit to ship (Windows Git Bash or any shell with ssh):

```sh
SHA=$(git rev-parse --short HEAD)
git -c core.autocrlf=false archive --format=tar.gz --prefix=bapc-vpn-$SHA/ -o bapc-vpn-$SHA.tar.gz HEAD
scp bapc-vpn-$SHA.tar.gz root@116.203.78.222:/opt/bapc-vpn-releases/
ssh root@116.203.78.222 "tar -xzf /opt/bapc-vpn-releases/bapc-vpn-$SHA.tar.gz -C /tmp bapc-vpn-$SHA/deploy/release.sh && \
  systemd-run --unit=bapc-vpn-release bash /tmp/bapc-vpn-$SHA/deploy/release.sh /opt/bapc-vpn-releases/bapc-vpn-$SHA.tar.gz $SHA"
ssh root@116.203.78.222 journalctl -u bapc-vpn-release -f
```

[deploy/release.sh](../deploy/release.sh) runs on the server (a dropped SSH connection can't stop it halfway): fresh verified
backup → saves the running code and tags every image as a rollback point → unpacks (never overwrites `.env` or the override)
→ builds → starts (the migrate job runs first) → checks every service, `/healthz` and the portal. Any failure rolls back on its
own. Roll back by hand later with `bash /opt/bapc-vpn/deploy/rollback.sh [stamp]` (code and images only; the database is
forward-only, restore a backup if a migration must be undone).

After a release that changes plans: `docker compose exec customer-portal node dist/src/runtime/register-billing-plans.js`
(safe to repeat; Billing never changes a price in place).

## Settings and secrets (`/opt/bapc-vpn/deploy/.env`)

| Key | What | Shared with |
|---|---|---|
| POSTGRES_PASSWORD, CONTROL_API_TOKEN_SECRET, EVENT_SIGNING_SECRET, OOB_SHARED_SECRET | Core secrets (production refuses placeholders and short values) | none |
| DIAGNOSTICS/HEADQUARTERS/CLOUD_DEPLOYMENT/INTEGRATION_SHARED_SECRET | Signed messages from sibling BAPC apps (HQ in use; the other three set but no sender yet) | that app; copy in `C:\Users\bryan\.bapc-secrets\bapc-vpn-ecosystem-secrets.env` |
| ATTESTATION_PROVIDER | `windows-tpm` | none |
| VPN_GATEWAY_PUBLIC_KEY, VPN_GATEWAY_ENDPOINT | Written by `deploy/gateway/setup-gateway.sh` | none |
| BAPC_CLIENT_SECRET | Sign in with BAPC, client `bapc-vpn` | bapc.app |
| BAPC_BILLING_KEY | BAPC Billing app key, app `bapc-vpn` | BAPC Billing (hash only) |
| BAPC_BILLING_HOOK_SECRET | Verifies Billing's `plan.changed` hook | BAPC Billing (`app_hooks`) |
| BAPC_NOTIFICATIONS_KEY | Customer email, app `bapc-vpn`, from no-reply@bapc.app | BAPC Notifications (hash only) |
| WAREHOUSE_URL, WAREHOUSE_SOURCE_ID, WAREHOUSE_SIGNING_SECRET | Daily usage totals | Warehouse Worker secret `WAREHOUSE_SECRET_BAPC_VPN_FEED` |
| OBOP_INGEST_TOKEN, OBOP_SYSTEM_ID | Error reporting to BAPC Observability. **Not set yet** (owner issues the token). | BAPC Observability |
| RELAY_AGENT_TOKEN, EGRESS_AGENT_TOKEN | Relay/egress self-registration | none |

Every change to `.env` is preceded by a dated copy (`.env.bak-<stamp>`). After changing it: `docker compose up -d --no-build`.

## Backups (nightly, tested, off-server)

- `bapc-vpn-backup.timer`, 03:15 UTC ([deploy/backup/](../deploy/backup/bapc-vpn-backup.sh)): `pg_dump` → archive check → **full
  test restore into a throwaway database with table and migration counts compared** → AES-256 → decrypt check →
  `/var/backups/bapc-vpn/<stamp>/` (14 days kept) → sent to BAPC Backup (`/ingest/bapc-vpn`), which reads it back and alerts
  through Status if a copy is missing or more than 26 h old.
- Key: `/etc/bapc-vpn-backup/key` on the server; copy in `C:\Users\bryan\.bapc-secrets\bapc-vpn-backup-encryption-key.txt`.
- Restore: `BACKUP_ENCRYPTION_KEY=… DATABASE_URL=… scripts/db-restore.sh <folder>/db.dump.enc`, then `npm run migrate:status`.
  Rehearsed into a scratch database on 21 Nov 2026 (all counts matched).

## Watching it

| What | Where |
|---|---|
| Uptime | status.bapc.app: `vpn` (customer site) and `vpn-control` (control plane), every 5 min; 2 failures in a row open an incident. |
| Errors and crashes | Every service reports error log lines and crashes to BAPC Observability once `OBOP_*` is set (src/infrastructure/error-reporting.ts). Until then they are in `docker logs`. |
| Usage | maintenance-worker sends yesterday's `activity.daily` totals (active_users, signups, sign_ins, onboarded) to the Warehouse every 6 h; seen in BAPC Analytics. |
| Logs | `docker compose logs <service>` (structured JSON), `journalctl -u bapc-gateway-sync`, `journalctl -u bapc-vpn-backup`. |

## Customers, money and support

- **Plans** (in BAPC Billing, app `bapc-vpn`): Monthly $8.99, Yearly $35.88, both with a 7-day free trial (first subscription
  only, card up front). The site shows the trial only while Billing reports it.
- **Payment state**: Billing's signed `plan.changed` hook pauses or resumes an account's devices at once; the portal also
  re-checks on every account visit and every 15 min.
- **Customer email** (BAPC Notifications): welcome, new device, devices paused/back on, account closed. Receipts and trial
  reminders come from BAPC Billing.
- **Customer data**: Download my data and Close my account on the account page (GDPR/CCPA); every action is in `portal_audit`.
- **Staff admin**: vpn.bapc.app/admin, bapc.app admins only (404 for everyone else): search accounts, devices, plan status,
  activity, revoke a device, re-check payment, close an account (with a reason). Staff actions are audited as `staff`.
- **Support**: BAPC Help Desk, support.bapc.app / support@bapc.app. User help: vpn.bapc.app/help.

## Enterprise Standard exceptions that apply

R3 (sign-in features live in Sign in with BAPC), R6 (no two-step sign-in), R8 (one-person customer accounts: no customer
team roles). See `bapc-cloud-and-deploy/deploy/audit/exceptions.md`.

## Staging

https://staging-vpn.bapc.app runs on the same server **without Docker** (systemd + host PostgreSQL 18; see
[deploy/native/README.md](../deploy/native/README.md)): its own database (`bapc_security_staging`), secrets
(`/etc/bapc-vpn/staging.env`) and ports (18080/18095/...). It has no VPN gateway and no Billing, sign-in, email, Warehouse or
Observability keys, and it tells search engines not to index it. Ship to staging first:
`systemd-run --unit=bapc-vpn-release-staging bash /opt/bapc-vpn-native-setup/native/release.sh staging <bundle> <sha>`
(same build, checks and automatic rollback as production's).

## Known open items

- Observability token not issued yet (errors are only in local logs).
- Production still runs on Docker. The move to BAPC infrastructure (App Hosting + Cheisgos + Secrets + Registry) is
  built and tested in code ([deploy/hosting/README.md](../deploy/hosting/README.md)); it needs the one-time setup there
  (owner's yes on each marked step), staging first, then a production window. `deploy/native/` (plain systemd) runs
  staging today and stays as the fallback.
- Trust Core signs with a development CA held in Postgres (no KMS/HSM); secrets live in `.env`, not the BAPC vault.
