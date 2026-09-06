# Production adapter requirements
 
The TypeScript domain and orchestration code is executable, but a live security product must bind the ports to audited platform components.
 
- HSM/KMS: offline root CA ceremony; online intermediate key references; certificate issuance and revocation; never store private keys in PostgreSQL.
- Linux: WireGuard/netlink, controlled precompiled eBPF programs with map updates, nftables fallback, systemd service hardening and resolver integration.
- Windows: WireGuard adapter, Windows Filtering Platform service, TPM 2.0 attestation and Windows service recovery.
- Apple: NetworkExtension packet tunnel, permitted content-filter/system-extension capabilities, Secure Enclave P-256 identity and entitlement/MDM handling.
- DNS: CoreDNS-compatible authenticated plugin, DoH/DoT upstreams, signed threat-feed ingestion and auditable sinkhole handling.
- Relays: multi-region blind forwarding, authenticated health, DDoS controls, capacity management and fixed-IP egress failover.
- OOB: separate endpoints, credentials, DNS/routing dependencies and rollout policy from the primary mesh.
- Persistence: PostgreSQL repositories, migrations, partition maintenance, backups and disaster recovery.
- Observability: metrics, traces, immutable log export, incident retention and Headquarters/SOC dashboards.
 
No development adapter is authorized for production use.
