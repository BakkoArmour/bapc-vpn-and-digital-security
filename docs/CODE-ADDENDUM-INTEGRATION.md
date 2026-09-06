# BAPC VPN & Digital Security™ — Code Addendum Integration

1. Keep the existing Version 0.2.0 repository as the base.
2. Add the new files in this addendum and replace package.json, src/config.ts and src/index.ts.
3. Run db/003_transactional_outbox.sql and db/004_security_hardening.sql after 001 and 002.
4. Run npm install, then npm run check.
5. Do not use DevelopmentCertificateIssuer, AllowAttestation, NoopPeerDistributor,
   InMemoryEnforcer or any other development adapter in production.
6. Connect TrustCoreIssuer to the approved HSM/KMS and X.509 builder.
7. Bind PlatformAdapter to audited Linux, Windows and Apple native components.
8. Establish and verify OOB control before committing production firewall/mesh changes.
9. Deploy relays and egress gateways in multiple failure domains before enabling failover.
10. Connect signed ecosystem events to BAPC Diagnostics™, BAPC Cloud & Deployment™,
    BAPC Integration™ and BAPC Headquarters™.
11. Run integration, network, containment, resilience and SOC E2E tests.
12. Complete the Universal Final Audit before production activation.

Production completion is not declared solely because TypeScript builds.
The native privileged adapters, protected key infrastructure, live credentials,
platform signing/entitlements, regional networking and live failure drills must also pass.

What this addendum adds
Real PostgreSQL connection handling, transactional execution and repository persistence.
Transactional outbox tables and dispatcher for reliable ecosystem/security event delivery.
Replay/idempotency database primitives for hardened control-plane APIs.
Authenticated role-gated REST routing with bounded JSON bodies and hardened response headers.
Protected-key Trust Core orchestration that keeps private keys outside the application/database.
Mesh address allocation, topology reconciliation and quarantine control.
A portable platform-adapter contract plus production endpoint command reconciliation.
Secure DNS decision enforcement, encrypted-upstream failover and privacy-preserving audit hashes.
Relay health/capacity registry and fixed-egress fail-closed selection.
Out-of-band last-known-good checkpointing, verification and rollback.
Threat scoring with re-authentication, JIT termination, isolation, credential revocation and mesh identity rotation.
SOC backend snapshot, quarantine and typed-confirmation emergency lockdown controls.
Signed BAPC ecosystem event publishing.
Production server composition, graceful shutdown, health checks and expanded automated tests.

Still requires native/protected deployment binding
These are not ordinary TypeScript files and should not be faked inside the control-plane package: Linux WireGuard/netlink + nftables/eBPF; Windows WireGuard/WFP + TPM-backed service; Apple NetworkExtension/System Extension + Secure Enclave; HSM/KMS vendor driver; X.509/ACME/EST service; signed installers, entitlements, code signing, regional relay hosts, egress IPs and production DNS upstream credentials. The interfaces and orchestration points for those components are included above.
