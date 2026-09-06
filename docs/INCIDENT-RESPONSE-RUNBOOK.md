# BAPC VPN & Digital Security — Incident Response Runbook

Each procedure below names the actual endpoint, service, or script in this
repository that implements it. Where a step has no implementation yet, it
says so explicitly rather than describing a procedure that doesn't exist.

## Compromised device / node

1. `POST /api/v1/nodes/:id/quarantine {"reason": "..."}` (role
   `security-approver`, or the Quarantine button in the SOC console).
   `ThreatResponseService.handle` (`src/application/threat-response.ts`)
   marks the device compromised, terminates active JIT grants in its zone,
   and calls `PolicyEnforcer.isolateNode` — `production-server.ts` now wires
   this to `PgPolicyEnforcer` (`src/infrastructure/pg-policy-enforcer.ts`),
   which enqueues a `QUARANTINE_NODE` command into the same durable command
   queue (`controller_commands`) both the REST endpoint-agent heartbeat and
   the mesh-grpc `streamHeartbeat` drain, so the node is actually cut off on
   whichever channel it's connected through — not the in-memory dev
   `InMemoryEnforcer` this used to default to (see
   `docs/CODE-ADDENDUM-INTEGRATION.md` item 5). What still requires a real
   `PlatformAdapter` binding is the node *acting* on that command once
   delivered — actually tearing down its WireGuard interface/firewall rules
   on receipt, which is native, per-platform code (see
   `docs/UNIVERSAL-FINAL-AUDIT.md`).
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
   `ThreatResponseService.restore` verifies the token's HMAC signature via
   `DiagnosticsClearanceVerifier` (`integrations/diagnostics-clearance.ts`) —
   it is a base64url-encoded, HMAC-signed `SignedEcosystemEvent` from BAPC
   Diagnostics™, checked for signature validity, replay window, and that it
   is scoped to this exact node. Set `DIAGNOSTICS_SHARED_SECRET` to the value
   Diagnostics™ actually signs with; a token failing any of those checks is
   rejected, not just one missing the `diag-clearance:` prefix.

## Certificate compromise

1. `TrustCoreIssuer.revoke(serial, reason)` (`services/trust-core/issuer.ts`)
   — marks the certificate revoked via `PgCertificateStore` (sets
   `is_revoked`, `revocation_reason`, `revoked_at`). There is no REST
   endpoint for triggering this yet; call it from an operator script or add
   one following the pattern of the other `/api/v1/*` routes.
2. Relying parties can check `GET /api/v1/certificates/crl` — a real,
   `openssl`-verified RFC 5280 X.509 CRL (`services/trust-core/crl-builder.ts`),
   public/unauthenticated by design (a CRL distribution point has no prior
   relationship with the clients checking it), signed and rebuilt on every
   request from the current `is_revoked=true` rows. There is still no OCSP
   responder (OCSP needs a live per-request signing path, not just a
   periodic list) — for now, CRL is the mechanism; shorten
   `CERTIFICATE_TTL_MINUTES` too if your relying parties can't fetch CRLs
   frequently enough for your risk tolerance. **Production note**: the CRL is
   currently signed by an ephemeral per-process dev key
   (`createSelfSignedDevCa` in `production-server.ts`) — it must be switched
   to sign with the same HSM-backed intermediate that issues the
   certificates it lists, or relying parties validating the CRL's own
   signature chain will reject it.
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

`POST /api/v1/soc/emergency-lockdown {"reason": "...", "confirmation": "LOCKDOWN"}`
(role `security-owner`, rate-limited to 2/minute). `SecuritySocBackend.emergencyLockdown`
requires the literal typed confirmation string `LOCKDOWN` and a reason
≥20 characters, then `PgSocActions.emergencyLockdown` isolates every
currently-active mesh node (via the configured `PolicyEnforcer`) and
terminates every active JIT grant, publishing `security.emergency_lockdown`
with counts of both for audit. It does not revoke certificates or
credentials — recovery is per-node via the normal
quarantine/restore-with-clearance flow above, node by node, once the
incident is understood. `production-server.ts`'s simpler `SocService`
(`/api/v1/soc/snapshot`) and the richer `SecuritySocBackend`
(`/api/v1/soc/snapshot/full`, backed by `PgSocData`'s direct queries against
relays/certificates/incidents) are two independent read layers from
different build documents — both are wired now, but expect some overlap
between what `snapshot` and `snapshot/full` return.
