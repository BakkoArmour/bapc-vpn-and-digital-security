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
  and encrypted `pg_dump`/`pg_restore` scripts.
- **APIs**: an HMAC-guarded REST API (idempotency-key replay handling,
  per-identity rate limiting, `/metrics`) and a real gRPC
  `MeshOrchestrationService` (enrollment, key rotation, streaming heartbeat).
- **Trust Core**: real X.509 issuance (`node-forge`) with the actual private
  key held behind a pluggable async signer — the same code path works for
  the development in-memory key provider here and a real HSM/KMS in
  production. See `runbooks/root-ca-ceremony.md` for the real ceremony.
- **Network plane**: real Linux (`wg`/`ip`/`nft`) and Windows
  (`wireguard.exe` + a PowerShell helper) platform adapters, a real UDP
  blind relay, and a real minimal SOCKS5 egress proxy.
- **Secure DNS**: a real UDP DNS server with threat-feed/DGA sinkholing and
  a DNS-over-HTTPS upstream client.
- **Recovery & intelligence**: an out-of-band recovery channel on its own
  port/secret, threat-signal correlation over a sliding time window, and a
  SOC/admin console.
- **Delivery**: GitHub Actions CI (build, tests including a live-Postgres
  integration test, `npm audit`, SBOM), Linux systemd + Windows (WinSW)
  endpoint-agent installers.

**What's still explicitly out of scope** (requires accounts, hardware, or a
native platform SDK this session cannot provide — see
`docs/UNIVERSAL-FINAL-AUDIT.md` for the full list): real HSM/KMS custody of
production keys, an Apple NetworkExtension client (macOS/iOS/iPadOS — see
`native/apple/adapter.ts`), signed/notarized installers, live multi-region
relay/egress hosting, and an independent penetration test.

The original build specifications and code packets this repository was
reconstructed from are archived under `docs/build-source/`.
