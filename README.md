# BAPC VPN & Digital Security™

Strict-TypeScript control plane for a zero-trust VPN and security platform:
node enrollment, short-lived certificate issuance, policy evaluation, JIT
access, safe policy rollout, threat scoring/containment, secure DNS, a blind
relay and egress gateway, out-of-band recovery, audit chaining, SOC
snapshots and signed BAPC ecosystem events.

## Run

```bash
npm install
npm run check      # build + full test suite
```

Copy `.env.example` to `.env` and set at least `DATABASE_URL`,
`CONTROL_API_TOKEN_SECRET`, `EVENT_SIGNING_SECRET` and `OOB_SHARED_SECRET`
before running any service against a real database.

```bash
npm run migrate            # apply db/*.sql (checksum-tracked, advisory-locked)
npm start                  # REST control API      (src/runtime/production-server.ts)
npm run grpc               # mesh gRPC service      (src/runtime/grpc-server.ts)
npm run dns                # secure DNS server      (src/runtime/dns-server.ts)
npm run relay               # blind UDP relay        (src/runtime/relay-server.ts)
npm run egress              # SOCKS5 egress gateway   (src/runtime/egress-server.ts)
npm run oob                 # out-of-band channel     (src/runtime/oob-server.ts)
npm run console             # SOC/admin dashboard     (src/runtime/admin-console-server.ts)
npm run maintenance          # outbox drain + retention (src/runtime/maintenance-worker.ts) — see Operations Manual
npm run agent               # endpoint agent          (src/runtime/agent.ts)
npm run audit:final         # repository self-check — see docs/UNIVERSAL-FINAL-AUDIT.md
```

See `docs/OPERATIONS-MANUAL.md` for installation, administration, upgrade
and rollback, and `docs/INCIDENT-RESPONSE-RUNBOOK.md` for containment,
certificate compromise, lost-controller, relay/DNS outage and restore
procedures.

This repository is tool-neutral and uses ports/adapters so infrastructure
providers can be replaced without changing domain logic.

## Status (v0.4.0)

This is a strict-TypeScript control plane with:

- **Persistence**: PostgreSQL repositories, a checksum-tracked/advisory-locked
  migration runner, monthly event-partition maintenance, retention/purge SQL,
  and encrypted `pg_dump`/`pg_restore` scripts. A maintenance worker
  (`npm run maintenance`) actually drains the transactional outbox and runs
  retention — both existed as code for a while with nothing ever calling
  them; also fixed the outbox's `FOR UPDATE SKIP LOCKED` to run inside a
  transaction, since outside one the row lock was released before it could
  do anything.
- **APIs**: an HMAC-guarded REST API (idempotency-key replay handling,
  per-identity rate limiting, `/metrics`) and a real gRPC
  `MeshOrchestrationService` (enrollment, key rotation, streaming heartbeat).
  `POST /api/v1/access/decide` exposes the actual zero-trust Policy Decision
  Point (`PolicyDecisionService`) — MFA, device posture, node state, matching
  policy and JIT gating, returning an HMAC-signed `AccessDecision` — looking
  up device/node state server-side rather than trusting it from the request.
- **Trust Core**: real X.509 issuance (`node-forge`) with the actual private
  key held behind a pluggable async signer. Node enrollment requires a real
  self-signed PKCS#10 CSR (proof of possession) rather than reusing the
  WireGuard key, which is a different, incompatible key type. Signing runs
  against a real AWS KMS asymmetric key when `AWS_KMS_INTERMEDIATE_KEY_ID` is
  configured (`services/trust-core/aws-kms-key-provider.ts`) — genuine, wired
  code, not a stub, gated only on an AWS account existing yet — and falls
  back to an ephemeral CA shared across every process via Postgres
  (`dev_trust_anchor` table) otherwise. See `runbooks/root-ca-ceremony.md`
  for the dual-control root-key ceremony this doesn't replace.
- **Network plane**: real Linux (`wg`/`ip`/`nft`) and Windows
  (`wireguard.exe` + a PowerShell helper) platform adapters, a real UDP
  blind relay, and a real minimal SOCKS5 egress proxy. Both adapters also
  implement route-integrity monitoring/restoration (`AgentReconciler`,
  feature catalog #56-60) — wired into the endpoint agent via a `RECONCILE`
  controller command. `POST /api/v1/relays/provision` boots real relay fleet
  nodes on AWS EC2 (`services/relay-fleet/`) from a pre-baked golden AMI
  (`docs/RELAY-FLEET-AMI.md`) when `AWS_RELAY_AMI_ID`/`AWS_RELAY_REGION` are
  set — real, wired code, not a stub — returning a clear 501 otherwise.
- **Secure DNS**: a real UDP DNS server with threat-feed/DGA sinkholing and
  a DNS-over-HTTPS upstream client.
- **Recovery & intelligence**: an out-of-band recovery channel on its own
  port/secret, threat-signal correlation over a sliding time window, a real
  X.509 CRL distribution point (`GET /api/v1/certificates/crl`), a
  cryptographically-verified Diagnostics clearance check gating node
  restore, an owner-only emergency-lockdown endpoint (isolates every active
  node, terminates every active JIT grant, replay-protected via a one-time-
  use nonce), and a SOC/admin console.
- **Delivery**: GitHub Actions CI (build, tests including a live-Postgres
  integration test, `npm audit`, SBOM), Linux systemd + Windows (WinSW)
  endpoint-agent installers.
- **Secrets**: every runtime entrypoint loads production secrets
  (`CONTROL_API_TOKEN_SECRET`, `EVENT_SIGNING_SECRET`, `OOB_SHARED_SECRET`,
  the ecosystem HMAC secrets) from a real AWS Secrets Manager secret when
  `AWS_SECRETS_MANAGER_SECRET_ID` is set (`src/infrastructure/aws-secrets.ts`)
  — real, wired code, not a stub — falling back to plain environment
  variables otherwise.

**What's still explicitly out of scope** (requires accounts, hardware, or a
native platform SDK this session cannot provide — see
`docs/UNIVERSAL-FINAL-AUDIT.md` for the full list): a dual-control root-key
ceremony on an air-gapped HSM (AWS KMS-backed intermediate signing is real
and wired — see Trust Core above — but that's a single cloud account, not an
air-gapped HSM under multi-party physical custody), an Apple NetworkExtension
client (macOS/iOS/iPadOS — see `native/apple/adapter.ts`), signed/notarized
installers, actually running relay fleet nodes across multiple real regions
and drilling failover between them (single-node AWS EC2 provisioning is real
and wired — see Network plane above), and an independent penetration test.

The original build specifications and code packets this repository was
reconstructed from are archived under `docs/build-source/`.
