# BAPC VPN & Digital Security — Operations Manual

## Services in this repository

| Service | Entry point | npm script | Default bind |
|---|---|---|---|
| Control-plane REST API | `src/runtime/production-server.ts` | `npm start` | `127.0.0.1:8080` (dev) |
| Mesh gRPC (enroll/rotate/heartbeat) | `src/runtime/grpc-server.ts` | `npm run grpc` | `50051` |
| Secure DNS | `src/runtime/dns-server.ts` | `npm run dns` | `127.0.0.1:53` |
| Blind relay | `src/runtime/relay-server.ts` | `npm run relay` | `0.0.0.0:51900` |
| Egress gateway (SOCKS5) | `src/runtime/egress-server.ts` | `npm run egress` | `0.0.0.0:1080` |
| Out-of-band recovery channel | `src/runtime/oob-server.ts` | `npm run oob` | `127.0.0.1:8181` |
| SOC/admin console (static UI) | `src/runtime/admin-console-server.ts` | `npm run console` | `127.0.0.1:8090` |
| Maintenance worker (outbox drain + retention) | `src/runtime/maintenance-worker.ts` | `npm run maintenance` | n/a (background) |
| Endpoint agent | `src/runtime/agent.ts` | `npm run agent` | n/a (client) |

**Run the maintenance worker.** `TransactionalOutbox.publish()` (used by
every `EventBus.publish()` call across this codebase) only inserts a row into
`event_outbox` — nothing delivers it anywhere until something calls
`OutboxDispatcher.flush()`. Without `npm run maintenance` (or the
`maintenance-worker` compose service) running continuously, published events
accumulate in the database forever and partition/row retention never runs.
This is easy to miss since every other service works fine without it.

Each reads its configuration from environment variables — see `.env.example`
for the full list and `src/config.ts` for the REST API's validation rules
(production refuses default development secrets).

**Bearer token `sub` must be a UUID.** `jit_grants.user_id` (and other
identity-keyed columns) are `uuid NOT NULL` — a bearer token whose `sub`
claim isn't a valid UUID fails with a raw-looking Postgres error
("invalid input syntax for type uuid") on the first call that persists it,
surfaced as a 400. Internal BAPC identity is assumed to assign UUIDs; if you
wire in an external OIDC/SAML IdP whose `sub` is a different format (email,
`auth0|...`, etc.), map it to a stable internal UUID before minting the
bearer token — this repository doesn't do that mapping for you.

## Installation

1. Provision PostgreSQL 16+ and set `DATABASE_URL`.
2. `npm ci && npm run build`
3. Apply migrations: `npm run migrate` (or `npm run migrate:status` to check
   without applying). `db/*.sql` is applied in filename order, tracked in
   `public.schema_migrations`, and protected by a Postgres advisory lock so
   concurrent deploys can't double-apply — see `src/infrastructure/postgres/migrate.ts`.
4. Generate or obtain Trust Core certificates (`runbooks/root-ca-ceremony.md`
   for production; `services/trust-core/ceremony.ts` for a dev/staging CA).
5. Set `CONTROL_API_TOKEN_SECRET`, `EVENT_SIGNING_SECRET`, and
   `OOB_SHARED_SECRET` from your secret manager — all ≥32 characters, all
   different values.
6. Start the services you need (systemd units for the control plane are not
   included here — only the endpoint agent ships one, in `installers/linux/`;
   the control-plane services are typically containerized, see `deploy/`).
7. Install endpoint agents: `installers/linux/install.sh` (Linux) or
   `installers/windows/install.ps1` (Windows — requires WinSW, see that
   script's header). macOS/iOS/iPadOS require a native Swift NetworkExtension
   client that does not exist in this repository — see `native/apple/adapter.ts`.

## Administration

- **Approve/reject JIT access**: `POST /api/v1/jit/:id/approve` or
  `/terminate` (role `security-approver`), or via the SOC console.
- **Quarantine a node**: `POST /api/v1/nodes/:id/quarantine` — isolates via
  the configured `PolicyEnforcer`, marks the device compromised, and revokes
  active JIT grants in that zone (`ThreatResponseService.handle`).
- **Restore a node**: `POST /api/v1/nodes/:id/restore` with a
  `clearanceToken` beginning `diag-clearance:` (the signed clearance BAPC
  Diagnostics™ would issue after investigation).
- **Rotate a peer's WireGuard key**: gRPC `RotatePeerKey` (see
  `src/api/grpc/server.ts`).
- **Check a zero-trust access decision**: `POST /api/v1/access/decide`
  (`PolicyDecisionService`) — the actual Policy Decision Point a Policy
  Enforcement Point (endpoint agent, gateway) calls before allowing traffic.
  Device and node state are looked up server-side by ID; the response is an
  HMAC-signed `AccessDecision` (`HmacDecisionSigner`, same secret as
  `CONTROL_API_TOKEN_SECRET`) a PEP can verify independently.
- **Certificate expiry**: `PgCertificateStore.expiringWithin(days)` — wire
  this into your alerting; there is no automated alert emitter in this
  repository yet.

## Upgrades

1. `npm run migrate:status` before deploying new code, to confirm no drifted
   migrations (a changed already-applied `db/*.sql` file is a hard error —
   `MigrationRunner` refuses to proceed rather than silently reapply it).
2. Deploy new application code.
3. `npm run migrate` to apply any new `db/*.sql` files.
4. Roll endpoint agents after the control plane is confirmed healthy
   (`GET /api/v1/status`).

## Rollback

- **Application code**: redeploy the previous build artifact/image.
- **Database**: this repository does not generate down-migrations (each
  `db/*.sql` is forward-only). Roll back schema changes by restoring from a
  backup (`scripts/db-restore.sh`) taken before the upgrade, not by hand-
  writing reverse SQL against a live system.
- **Network policy**: `SafeApplyService` already stages, canary-verifies, and
  auto-rolls-back a policy commit within its configured timeout
  (`SAFE_APPLY_TIMEOUT_MS`) — a bad policy push should self-heal without
  manual rollback in the common case.

## Backup and restore

```bash
DATABASE_URL=... BACKUP_ENCRYPTION_KEY=... ./scripts/db-backup.sh
DATABASE_URL=... BACKUP_ENCRYPTION_KEY=... ./scripts/db-restore.sh backups/bapc_security_core_<timestamp>.dump.enc
```

Test restores into an isolated database before trusting a backup — this repo
does not automate that drill; `docs/UNIVERSAL-FINAL-AUDIT.md` lists it as a
required, currently-unverified acceptance gate.

## Monitoring

- `GET /healthz` — liveness (unauthenticated).
- `GET /api/v1/status` — includes a live database health check.
- `GET /metrics` — Prometheus text format, request/error counters
  (`src/api/rest/metrics.ts`). Not exposed unless the router is constructed
  with `exposeMetrics=true` (production-server.ts does this); restrict access
  at the network layer since it is not otherwise authenticated.
- Structured JSON logs on stdout from every `src/runtime/*.ts` entry point.
  There is no log-shipping/aggregation wiring in this repository — that is
  an infrastructure decision for the deployment target (CloudWatch, Loki,
  etc.), not something this codebase can supply generically.
