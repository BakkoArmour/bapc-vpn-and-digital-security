# BAPC VPN on BAPC infrastructure

How BAPC VPN runs without Docker on BAPC's own systems:

| Piece | BAPC system | How |
|---|---|---|
| The nine services | **App Hosting** (host.bapc.app, #38) | One App Hosting app per service, all from one image, rootless Podman on the `bapc-vpn` machine through the host agent. Fixed loopback ports (TCP/UDP), so cloudflared, the WireGuard gateway sync and the backup keep using the same addresses. Services find each other by network alias (`vpn-api`, `vpn-oob`, ...). |
| Database | **Cheisgos** (sql.bapc.app, #36) | PostgreSQL 18 cluster on the same machine, loopback only (`127.0.0.1:15432` production, `:15433` staging), TLS + SCRAM. Containers reach it as `host.containers.internal`; only those ports are open to them. Roles: `bapc_vpn_migrator` (migrations, acting as `bapc_vpn_owner`) and `bapc_vpn_rw` (the services). |
| Secrets | **Secrets** (secrets.bapc.app) | Environments `bapc-vpn-prod` and `bapc-vpn-staging`. The App Hosting agent reads them with a read-only app key just before a container starts; Cheisgos writes the role passwords there with a write key. Nothing secret is in a spec, an image or a command line. |
| Image | **Registry** (registry.bapc.app, #26) | `bapc-vpn/core`, built with Podman on the machine (no Docker, no GitHub), signed with the machine's sigstore key, promoted per stage (production needs the owner). |
| Backups | **Backup** + Cheisgos | The nightly verified backup now reads Cheisgos (test restore on the machine's local PostgreSQL) and goes to BAPC Backup as before; Cheisgos adds pgBackRest and point-in-time restore. |

Files: [apps.mjs](apps.mjs) (the nine specs), [release.mjs](release.mjs) (ships one build), [build-image.sh](build-image.sh)
(build, sign, push, promote), [cutover.sh](cutover.sh) (moves a stage over), tests: `npm run test:hosting`.

## One-time setup (each step needs the owner's yes where marked)

1. **Deploy the App Hosting and Cheisgos changes** (branches `host-vpn-ready` in bapc-app-hosting, `sql-vault-link` in
   bapc-postgres). *Owner's yes: production deploy.*
2. **BAPC Secrets** (console): environments `bapc-vpn-prod`, `bapc-vpn-staging`; per environment a read-only app key
   (App Hosting agent) and a write-enabled key (Cheisgos agent). Copy the current values from
   `/opt/bapc-vpn/deploy/.env` (production) and `/etc/bapc-vpn/staging.env` into them under the names
   `node -e "import('./deploy/hosting/apps.mjs').then(m=>console.log(m.requiredSecrets('production',{obop:false,portal:true,warehouse:true,agents:true}).join('\n')))"`
   prints (the PG_* passwords come from Cheisgos itself). *Owner's yes: security settings.*
3. **BAPC Login clients** for app `bapc-vpn`: audience `bapc-host` (`host:read host:deploy host:manage`) →
   `/etc/bapc-vpn/host-client.env`; audience `bapc-registry` (`registry:push registry:promote`) →
   `/etc/bapc-vpn/registry-client.env` and `podman login --authfile /etc/bapc-vpn/registry-push.json`; one with
   `registry:pull` for the agent → `sudo -u bapc-host podman login --authfile /var/lib/bapc-host/auth.json registry.bapc.app`.
4. **Signing key**: `skopeo generate-sigstore-key --output-prefix /etc/bapc-vpn/signing/sigstore` (passphrase in
   `sigstore.pass`, root only); add `sigstore.pub` as a trusted key in the Registry console;
   `/etc/containers/registries.d/registry.bapc.app.yaml`: `docker: {registry.bapc.app: {use-sigstore-attachments: true}}`.
5. **App Hosting**: project `bapc-vpn` (owner app `bapc-vpn`), cluster `bapc-vpn` (runtime podman, stages staging and
   production), environment quotas of at least 2.5 GiB memory and 6 CPU each. Add the agent, then on the machine:
   `NODE=bapc-vpn AGENT_ID=agt_… SELF_V4=116.203.78.222 SELF_V6=2a01:4f8:1c1a:1f97::/64 LOOPBACK_TCP=55432,55433 bash agent/machine/install.sh`
   (from bapc-app-hosting). Put the read-only keys in `/etc/bapc-host/credentials/secrets/<environment>.key` (root only, mode 600; systemd hands them to the agent). Watch it a day
   in observe mode, then switch it to apply. *Owner's yes: server change, apply mode.*
6. **Cheisgos**: enroll the machine's agent (with `vault` → `{"bapc-vpn/production": "bapc-vpn-prod", "bapc-vpn/staging": "bapc-vpn-staging"}`
   and the write keys), clusters `vpn-core` (port 15432) and `vpn-staging` (15433), database `bapc_vpn` in each, roles
   `bapc_vpn_migrator` (migrator) and `bapc_vpn_rw` (runtime_rw). Prerequisites from Cheisgos' go-live: Podman,
   pgBackRest, an encrypted volume for its storage, TLS files. *Owner's yes: server change.*
7. `/etc/bapc-vpn/hosting-<stage>.json`: `{"project_id": "prj_…", "node": "bapc-vpn", "optional": {…}, "publicEnv":
   {"VPN_GATEWAY_PUBLIC_KEY": "…", "VPN_GATEWAY_ENDPOINT": "116.203.78.222:51820", "OBOP_SYSTEM_ID": "…",
   "WAREHOUSE_URL": "…", "WAREHOUSE_SOURCE_ID": "…"}}` (production; staging has no gateway or Warehouse).
8. `/etc/bapc-vpn-backup/check-url`: the nightly test restore needs a server **of the same PostgreSQL version** as Cheisgos
   (18.7 adds column options 18.6 refuses): a throwaway container `bapc-backup-check` from the Cheisgos image digest on
   127.0.0.1:54390 (`postgres` with a random password in `/etc/bapc-vpn-backup/check-pw`), restart always.
9. App Hosting must be able to read the image in the Registry (Registry console → Namespaces → bapc-vpn → let tenant
   `bapc-host` pull); production refuses a digest App Hosting cannot confirm.

## Moving a stage over

Staging first, then production in a maintenance window:

```sh
SHA=$(git rev-parse --short HEAD)
git -c core.autocrlf=false archive --format=tar.gz --prefix=bapc-vpn-$SHA/ -o bapc-vpn-$SHA.tar.gz HEAD
scp bapc-vpn-$SHA.tar.gz root@116.203.78.222:/opt/bapc-vpn-releases/
ssh root@116.203.78.222   # then, from the unpacked bundle's deploy/hosting:
DIGEST=$(bash build-image.sh /opt/bapc-vpn-releases/bapc-vpn-$SHA.tar.gz $SHA staging | tail -1)
bash cutover.sh staging $DIGEST $SHA
```

## Every release after that

`build-image.sh … <stage>` then `node release.mjs --stage <stage> --digest <digest> --release <sha>` (credentials from
`/etc/bapc-vpn/host-client.env`). Production waits twice for the owner: the Registry promotion, then "Approve all 9"
on App Hosting's Approvals page. A service that fails to come up is rolled back by App Hosting; the rest keep running.

## Going back

App Hosting console → each `vpn-*` app → scale to 0 in that environment (frees the ports), then
`cd /opt/bapc-vpn/deploy && docker compose start` (production) or `systemctl start bapc-vpn@staging.target`.
Data written on Cheisgos since the move is not in the old database: copy it back first if needed (same pg_dump /
pg_restore as cutover.sh, the other way).
