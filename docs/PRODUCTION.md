# BAPC VPN in production

How the live BAPC VPN runs, ships, is backed up, watched and supported. Current as of 21 Nov 2026 (release on
branch `vpn/launch-readiness`). The older [OPERATIONS-MANUAL.md](OPERATIONS-MANUAL.md) still describes each service and
the operator API; where the two differ, this file is the live truth.

## Where it runs

| Piece | Where |
|---|---|
| Server | `bapc-vpn`, Hetzner, 116.203.78.222 (IPv6 2a01:4f8:1c1a:1f97::1), Ubuntu 26.04. Code in `/opt/bapc-vpn`, settings and secrets in `/opt/bapc-vpn/deploy/.env` (root only). |
| Services | **BAPC App Hosting** (since 21 Nov 2026 23:12 UTC, release a770ba4): nine apps in project `bapc-vpn` (stage production), rootless Podman under the `bapc-host` user, on the same 127.0.0.1 ports as before (8080, 8095, 50051, 8181, 8090, 5353/udp, 51900/udp, 1080). Image `registry.bapc.app/bapc-vpn/core` (signed). Secrets: BAPC Secrets environment `bapc-vpn-prod`. The old Docker stack in `/opt/bapc-vpn/deploy` is stopped, kept and set not to restart (going back: [deploy/hosting/README.md](../deploy/hosting/README.md)); remove it only after a quiet week, with the owner's yes. |
| Database | **BAPC Cheisgos** cluster `vpn-core` (standard: primary 127.0.0.1:54321 + streaming standby 54322 on the private `bapc-sql` network; PostgreSQL 18.7, TLS, encrypted storage), database `bapc_vpn`, roles `bapc_vpn_migrator` (migrations, as `bapc_vpn_owner`) and `bapc_vpn_rw` (services). pgBackRest WAL archiving; nightly encrypted off-server copy to BAPC Backup (`bapc-sql-offsite@c07de2bbbcb949afb200.timer`, 03:40 UTC). |
| VPN gateway | WireGuard `wg0` on the host, UDP 51820 (the only public port besides SSH). `bapc-gateway-sync` pulls the allowed device list every 10 s; `bapc-gateway-firewall` keeps devices off the host and each other. See [DEVICE-JOIN.md](DEVICE-JOIN.md). |
| Public addresses | Cloudflare tunnel `bapc-vpn-and-digital-security` (917ce328…): `vpn.bapc.app` → customer portal (127.0.0.1:8095), `vpn.bapc-headquarters.com` → control API (127.0.0.1:8080). DNS: `vpn` CNAME in bapc.app and bapc-headquarters.com, proxied. |
| Code | Code Adytum `bapc/bapc-vpn-and-digital-security` (main copy) and GitHub (backup). |

## Shipping a release

Now: [deploy/hosting/README.md](../deploy/hosting/README.md) ("Every release after that"): build-image.sh (Podman build, sign, push, promote), then release.mjs; production waits for the Registry promotion and "Approve all" in App Hosting. The Docker steps below are kept for going back only.

## Shipping a release on Docker (fallback only)

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

- `bapc-vpn-backup.timer`, 03:15 UTC, now dumping from Cheisgos (`/etc/bapc-vpn-backup/env`: migrator acting as owner; test restore on the throwaway check server `bapc-backup-check`, the same PostgreSQL image, 127.0.0.1:54390) ([deploy/backup/](../deploy/backup/bapc-vpn-backup.sh)): `pg_dump` → archive check → **full
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

https://staging-vpn.bapc.app runs **on BAPC infrastructure, without Docker** (since 21 Nov 2026, release a770ba4):
the nine services are App Hosting apps (project `bapc-vpn`, stage staging, cluster `bapc-vpn`, rootless Podman under the
`bapc-host` user, ports 18080/18095/60051/18181/18090/15353 udp/61900 udp/11080 on 127.0.0.1); the database is the
Cheisgos cluster `vpn-staging` (PostgreSQL 18, 127.0.0.1:54320, TLS, encrypted storage, pgBackRest WAL archiving),
database `bapc_vpn`, roles `bapc_vpn_migrator` / `bapc_vpn_rw`; secrets in BAPC Secrets environment `bapc-vpn-staging`;
image `registry.bapc.app/bapc-vpn/core` (signed). No gateway, Billing, sign-in, email, Warehouse or Observability keys;
not indexed. Ship to staging: [deploy/hosting/README.md](../deploy/hosting/README.md) ("Every release after that").
The earlier systemd copy (`deploy/native/`) is kept, disabled, as a fallback.

## Known open items

- Observability token not issued yet (errors are only in local logs).
- Production's apps point at the Cheisgos primary's port (54321); after a Cheisgos failover the settings file needs the new
  primary port (follow-up: a stable database address).
- Docker stack kept stopped as the fallback until a quiet week has passed (removal needs the owner's yes).
- Trust Core signs with a development CA held in Postgres (no KMS/HSM); secrets live in `.env`, not the BAPC vault.
