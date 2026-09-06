# BAPC VPN & Digital Security — Incident Response Runbook

Each procedure below names the actual endpoint, service, or script in this
repository that implements it. Where a step has no implementation yet, it
says so explicitly rather than describing a procedure that doesn't exist.

## Compromised device / node

1. `POST /api/v1/nodes/:id/quarantine {"reason": "..."}` (role
   `security-approver`, or the Quarantine button in the SOC console).
   `ThreatResponseService.handle` (`src/application/threat-response.ts`)
   marks the device compromised, terminates active JIT grants in its zone,
   and calls `PolicyEnforcer.isolateNode` — in production this must be bound
   to a real `PlatformAdapter`/mesh-controller isolation path
   (`services/mesh-controller/controller.ts`'s `quarantine`), not the
   in-memory dev `InMemoryEnforcer` that `production-server.ts` currently
   wires by default (see `docs/CODE-ADDENDUM-INTEGRATION.md` item 5).
2. Confirm containment: the node should no longer appear in
   `GET /api/v1/nodes` as active, and `GET /api/v1/soc/snapshot`'s
   `compromisedDevices` count should increment.
3. Investigate. Diagnostics access during quarantine is a policy decision
   for your `PolicyEnforcer`/zone rules (`ZONE_FORENSIC_ISOLATION` in
   `src/domain/types.ts`) — this repository defines the zone but does not
   ship a concrete "diagnostics-only" firewall rule set; author one in your
   policy library before relying on it.
4. Restore only with a verified clearance:
   `POST /api/v1/nodes/:id/restore {"clearanceToken": "diag-clearance:..."}`.
   `ThreatResponseService.restore` rejects any token not prefixed
   `diag-clearance:` — wire this prefix check to real signature verification
   against BAPC Diagnostics™'s signing key before production use; today it is
   a format check only.

## Certificate compromise

1. `TrustCoreIssuer.revoke(serial, reason)` (`services/trust-core/issuer.ts`)
   — marks the certificate revoked via `PgCertificateStore`. There is no
   REST endpoint for this yet; call it from an operator script or add one
   following the pattern of the other `/api/v1/*` routes.
2. There is no CRL/OCSP responder in this repository — revocation is
   currently a database flag only. Any relying party that doesn't query
   `certificates.is_revoked` (or a CRL/OCSP service you build from it) will
   keep accepting the revoked certificate until it expires. Build that
   responder, or shorten `CERTIFICATE_TTL_MINUTES`, before relying on
   revocation alone.
3. Re-issue: enroll the affected node again (`EnrollmentService.register` /
   gRPC `RegisterNode`) to get a fresh key pair and certificate — never
   reuse the compromised key.

## Lost controller / control-plane outage

1. This is exactly what the out-of-band channel exists for
   (`services/oob-controller/*`, `runbooks` reference: the OOB path uses a
   separate port and a separate shared secret from the main API — see
   `.env.example`'s `OOB_SHARED_SECRET` note).
2. Check the OOB channel itself first: `GET /healthz` on `OOB_PORT`.
3. `OobController.rollback(scope)` restores the last-known-good document
   for that scope via the OOB channel, independent of the main control
   plane's health.
4. If the OOB channel is *also* down, this repository has no further
   fallback — that is a real gap, not an oversight: a true "last resort"
   path (e.g., local last-known-good config cached on each agent) is listed
   as unimplemented in `docs/UNIVERSAL-FINAL-AUDIT.md`.

## Relay outage

1. `RelayRegistry.choose(region)` (`services/relay/registry.ts`) already
   excludes relays whose heartbeat is >45s stale or over capacity —
   confirm the outage is visible there before assuming client-side failure.
2. `RelayRoutingService` (`src/application/relay-routing.ts`) falls back
   direct → local relay → regional relay automatically; verify affected
   nodes actually have a healthy alternative registered.
3. There is only a reference single-process `BlindRelayServer`
   (`services/relay/relay-server.ts`) in this repository — multi-region
   relay hosting, health-probe wiring, and failover deployment are
   infrastructure work for your deployment target, not code in this repo.

## DNS outage

1. `SecureDnsResolver` (`services/dns/resolver.ts`) already fails over
   across every configured `DnsUpstream` in order before giving up
   (returns `SERVFAIL` only if all fail and the query isn't sinkholed).
2. Configure more than one `DnsUpstream` (e.g., multiple `DohUpstream`
   instances pointed at different providers) in `src/runtime/dns-server.ts`
   — the reference wiring only configures one.
3. `BapcDnsServer` itself is a single process with no built-in HA; run
   multiple instances behind your platform's DNS/anycast failover.

## Database restore

See `docs/OPERATIONS-MANUAL.md`'s Backup and Restore section
(`scripts/db-backup.sh` / `scripts/db-restore.sh`). Always restore into an
isolated database first and run `npm run migrate:status` there before
pointing production traffic at it.

## Emergency lockdown

`SecuritySocBackend.emergencyLockdown` (`src/application/soc.ts`'s
sibling in the addendum) requires the literal typed confirmation string
`"LOCKDOWN"` and a reason ≥20 characters, and is not currently wired to a
REST route — the addendum's `SecuritySocBackend` and `production-server.ts`'s
simpler `SocService` are two independent read/action layers from different
build documents (see project memory note on this reconstruction). Wire
`SecuritySocBackend` (with real `SocData`/`SocActions` adapters) behind an
authenticated, owner-only route before treating emergency lockdown as
available — it is implemented but not yet exposed.
