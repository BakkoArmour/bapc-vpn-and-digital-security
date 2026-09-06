# BAPC VPN & Digital Security™

Portable TypeScript reference implementation for the control-plane domain. It includes node enrollment, short-lived certificate metadata, zero-trust policy evaluation, JIT access, safe policy rollout, threat scoring, quarantine, audit chaining, SOC snapshots and signed ecosystem events.

Cryptographic private keys, raw WireGuard private keys and hardware secrets are deliberately excluded. Production adapters must connect to an HSM/KMS, PostgreSQL, WireGuard/netlink, WFP, NetworkExtension, CoreDNS and the BAPC event bus.

## Run

```bash
npm install
npm run check
```

This repository is tool-neutral and uses ports/adapters so infrastructure providers can be replaced without changing domain logic.

## Status (v0.3.0)

This is a strict-TypeScript control-plane foundation with in-memory dev adapters, a Postgres persistence layer, an HMAC-guarded REST API, and orchestration contracts for the mesh, trust core, DNS, relay/egress, OOB recovery and threat-response engines. It is **not** a deployable production system: native network adapters (WireGuard/netlink, eBPF/nftables, WFP, NetworkExtension), HSM/KMS-backed key custody, signed installers, and live infrastructure are out of scope here and remain external, protected components. See `docs/CODE-ADDENDUM-INTEGRATION.md` and `docs/PRODUCTION-ADAPTERS.md` for what's still required before any production claim.

The original build specifications and code packets this repository was reconstructed from are archived under `docs/build-source/`.
