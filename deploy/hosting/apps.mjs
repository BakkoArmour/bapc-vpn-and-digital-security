// BAPC VPN on BAPC App Hosting (host.bapc.app): the nine services as HostedApp specs, all from one image.
// Pure: given the image digest, the stage and this deployment's settings, it returns { slug, workload, spec } per app.
// Secrets are references into BAPC Secrets ("<environment>/<NAME>"); the database comes from BAPC Cheisgos as the
// standard PG* variables (PGPASSWORD from BAPC Secrets), reached on the machine as host.containers.internal.

/** The BAPC Secrets environment, Cheisgos database and loopback ports for each stage. */
export const STAGES = {
  production: {
    vault: 'bapc-vpn-prod', zonePortOffset: 0, origin: 'https://vpn.bapc.app',
    db: { port: 15432, name: 'bapc_vpn', user: 'bapc_vpn_rw', rwRef: 'PG_VPN_CORE_BAPC_VPN_RW_PASSWORD', migrator: 'bapc_vpn_migrator', migratorSecret: 'PG_VPN_CORE_BAPC_VPN_MIGRATOR_PASSWORD' },
  },
  staging: {
    vault: 'bapc-vpn-staging', zonePortOffset: 10000, origin: 'https://staging-vpn.bapc.app',
    db: { port: 15433, name: 'bapc_vpn', user: 'bapc_vpn_rw', rwRef: 'PG_VPN_STAGING_BAPC_VPN_RW_PASSWORD', migrator: 'bapc_vpn_migrator', migratorSecret: 'PG_VPN_STAGING_BAPC_VPN_MIGRATOR_PASSWORD' },
  },
};

// Fixed loopback ports. Production keeps today's ports (cloudflared, the WireGuard gateway sync and the backup point
// at them); staging is the same plus 10000, matching the systemd staging copy it replaces.
const PORTS = { api: 8080, portal: 8095, grpc: 50051, oob: 8181, console: 8090, dns: 5353, relay: 51900, egress: 1080 };

const CORE_SECRETS = ['CONTROL_API_TOKEN_SECRET', 'EVENT_SIGNING_SECRET', 'OOB_SHARED_SECRET', 'DIAGNOSTICS_SHARED_SECRET',
  'HEADQUARTERS_SHARED_SECRET', 'CLOUD_DEPLOYMENT_SHARED_SECRET', 'INTEGRATION_SHARED_SECRET'];

/**
 * @param {{ digest: string, stage: 'production'|'staging', release: string, node: string,
 *           optional?: { obop?: boolean, portal?: boolean, warehouse?: boolean, agents?: boolean },
 *           publicEnv?: Record<string,string> }} o
 *   optional: which optional secrets exist in BAPC Secrets for this stage (a reference to a missing secret stops the
 *   container, so only what exists is referenced). publicEnv: non-secret settings such as VPN_GATEWAY_PUBLIC_KEY,
 *   VPN_GATEWAY_ENDPOINT, OBOP_SYSTEM_ID, WAREHOUSE_URL, WAREHOUSE_SOURCE_ID.
 */
export function vpnApps(o) {
  const base = STAGES[o.stage];
  if (!base) throw new Error(`stage must be production or staging, not ${o.stage}`);
  // o.db: what Cheisgos actually assigned (it picks the cluster's port), from the settings file.
  const st = { ...base, db: { ...base.db, ...(o.db ?? {}) } };
  if (!Number.isInteger(st.db.port) || st.db.port < 1024 || st.db.port > 65535) throw new Error('db.port must be the Cheisgos cluster port');
  if (!/^sha256:[a-f0-9]{64}$/.test(o.digest)) throw new Error('digest must be sha256:<64 hex>');
  const opt = { obop: false, portal: false, warehouse: false, agents: false, ...o.optional };
  const pub = o.publicEnv ?? {};
  const ref = (name) => `${st.vault}/${name}`;
  const sec = (envName, name = envName) => ({ name: envName, secretRef: ref(name) });
  const port = (k) => PORTS[k] + st.zonePortOffset;
  const net = (k, protocol = 'tcp') => ({ egressPolicy: 'restricted', ports: [{ containerPort: PORTS[k], hostPort: port(k), protocol }], aliases: [`vpn-${k}`] });
  const res = (cpu, mem) => ({ cpuRequest: '100m', cpuLimit: cpu, memoryRequest: '96Mi', memoryLimit: mem });
  const pick = (keys) => Object.fromEntries(keys.filter((k) => pub[k] !== undefined && pub[k] !== '').map((k) => [k, String(pub[k])]));

  const baseEnv = {
    NODE_ENV: 'production', ATTESTATION_PROVIDER: 'windows-tpm', BAPC_RELEASE: o.release, OBOP_SERVICE_KEY: 'web',
    PGHOST: 'host.containers.internal', PGPORT: String(st.db.port), PGDATABASE: st.db.name, PGUSER: st.db.user, PGSSLMODE: 'no-verify',
    ...pick(['OBOP_SYSTEM_ID']),
  };
  const baseSecrets = [sec('PGPASSWORD', st.db.rwRef), ...CORE_SECRETS.map((n) => sec(n)), ...(opt.obop ? [sec('OBOP_INGEST_TOKEN')] : [])];
  const gateway = pick(['VPN_GATEWAY_PUBLIC_KEY', 'VPN_GATEWAY_ENDPOINT', 'VPN_CLIENT_DNS']);
  const common = { artifact: { imageDigest: o.digest, signed: true }, rollout: { strategy: 'recreate', autoRollback: true }, placement: { node: o.node } };
  const app = (slug, name, workload, spec) => ({ slug, name, workload, spec: { ...common, ...spec } });
  const node = (file) => ['node', `dist/src/runtime/${file}`];

  return [
    // First: the API runs the database migrations (forward-only) and then serves; the others are shipped after it is ready.
    app('vpn-api', 'BAPC VPN control API', 'http', {
      // Migrations run as Cheisgos' migrator role acting as the database owner (PGOPTIONS role=...), so new tables
      // belong to the owner and the runtime role gets them through default privileges; the server then runs as runtime.
      runtime: { type: 'http', port: PORTS.api, replicas: 1, command: ['sh', '-c',
        `PGUSER=${st.db.migrator} PGPASSWORD="$PG_MIGRATOR_PASSWORD" PG_RUNTIME_ROLE=${st.db.user} PGOPTIONS="-c role=${st.db.name}_owner" node dist/src/runtime/migrate-cli.js db up && unset PG_MIGRATOR_PASSWORD && exec node dist/src/runtime/production-server.js`] },
      resources: res('1', '384Mi'), health: { readiness: '/healthz', liveness: '/healthz', startupSeconds: 120 }, network: net('api'),
      env: { ...baseEnv, ...gateway, BIND_HOST: '0.0.0.0', PORT: String(PORTS.api), OOB_CONTROLLER_URL: `http://vpn-oob:${PORTS.oob}` }, secrets: [...baseSecrets, sec('PG_MIGRATOR_PASSWORD', st.db.migratorSecret)],
    }),
    app('vpn-portal', 'BAPC VPN customer portal', 'http', {
      runtime: { type: 'http', port: PORTS.portal, replicas: 1, command: node('customer-portal.js') },
      resources: res('1', '384Mi'), health: { readiness: '/healthz', liveness: '/healthz', startupSeconds: 60 }, network: net('portal'),
      env: { ...baseEnv, ...gateway, PORTAL_BIND_HOST: '0.0.0.0', PORTAL_PORT: String(PORTS.portal), PORTAL_PUBLIC_ORIGIN: st.origin, BAPC_IDENTITY_URL: 'https://bapc.app', BAPC_BILLING_URL: 'https://billing.bapc.app' },
      secrets: [...baseSecrets, ...(opt.portal ? ['BAPC_CLIENT_SECRET', 'BAPC_BILLING_KEY', 'BAPC_BILLING_HOOK_SECRET', 'BAPC_NOTIFICATIONS_KEY'].map((n) => sec(n)) : [])],
    }),
    app('vpn-grpc', 'BAPC VPN mesh gRPC', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('grpc-server.js') }, resources: res('500m', '256Mi'), network: net('grpc'),
      env: { ...baseEnv, BIND_HOST: '0.0.0.0', GRPC_PORT: String(PORTS.grpc) }, secrets: baseSecrets,
    }),
    app('vpn-oob', 'BAPC VPN out-of-band controller', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('oob-server.js') }, resources: res('500m', '192Mi'), network: net('oob'),
      env: { ...baseEnv, OOB_BIND_HOST: '0.0.0.0', OOB_PORT: String(PORTS.oob) }, secrets: baseSecrets,
    }),
    app('vpn-worker', 'BAPC VPN maintenance worker', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('maintenance-worker.js') }, resources: res('500m', '256Mi'),
      network: { egressPolicy: 'restricted', aliases: ['vpn-worker'] },
      env: { ...baseEnv, ...pick(['WAREHOUSE_URL', 'WAREHOUSE_SOURCE_ID']) }, secrets: [...baseSecrets, ...(opt.warehouse ? [sec('WAREHOUSE_SIGNING_SECRET')] : [])],
    }),
    app('vpn-console', 'BAPC VPN SOC console', 'http', {
      runtime: { type: 'http', port: PORTS.console, replicas: 1, command: node('admin-console-server.js') }, resources: res('250m', '128Mi'),
      health: { readiness: '/', liveness: '/', startupSeconds: 30 }, network: net('console'),
      env: { NODE_ENV: 'production', ADMIN_CONSOLE_BIND_HOST: '0.0.0.0', ADMIN_CONSOLE_PORT: String(PORTS.console) },
    }),
    app('vpn-dns', 'BAPC VPN secure DNS', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('dns-server.js') }, resources: res('500m', '192Mi'), network: net('dns', 'udp'),
      env: { ...baseEnv, DNS_BIND_HOST: '0.0.0.0', DNS_PORT: String(PORTS.dns) }, secrets: baseSecrets,
    }),
    app('vpn-relay', 'BAPC VPN blind relay', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('relay-server.js') }, resources: res('500m', '192Mi'), network: net('relay', 'udp'),
      env: { NODE_ENV: 'production', RELAY_BIND_HOST: '0.0.0.0', RELAY_PORT: String(PORTS.relay), RELAY_ID: '0a2e90eb-ff1b-47e7-9224-6c633c21883c', RELAY_REGION: 'local',
        RELAY_PUBLIC_ENDPOINT: `vpn-relay:${PORTS.relay}`, BAPC_CONTROLLER_URL: `http://vpn-api:${PORTS.api}` },
      secrets: opt.agents ? [sec('BAPC_AGENT_TOKEN', 'RELAY_AGENT_TOKEN')] : [],
    }),
    app('vpn-egress', 'BAPC VPN egress gateway', 'worker', {
      runtime: { type: 'worker', replicas: 1, command: node('egress-server.js') }, resources: res('500m', '192Mi'), network: net('egress'),
      env: { NODE_ENV: 'production', EGRESS_BIND_HOST: '0.0.0.0', EGRESS_PORT: String(PORTS.egress), EGRESS_ID: 'c7275156-d439-421d-beab-8d37f12480e3', EGRESS_REGION: 'local',
        EGRESS_FIXED_IP: `vpn-egress:${PORTS.egress}`, BAPC_CONTROLLER_URL: `http://vpn-api:${PORTS.api}` },
      secrets: opt.agents ? [sec('BAPC_AGENT_TOKEN', 'EGRESS_AGENT_TOKEN')] : [],
    }),
  ];
}

/** The BAPC Secrets names one stage needs (what to put in BAPC Secrets before the first release). */
export function requiredSecrets(stage, optional = {}) {
  const st = STAGES[stage];
  const names = new Set([st.db.rwRef, st.db.migratorSecret, ...CORE_SECRETS]);
  if (optional.obop) names.add('OBOP_INGEST_TOKEN');
  if (optional.portal) for (const n of ['BAPC_CLIENT_SECRET', 'BAPC_BILLING_KEY', 'BAPC_BILLING_HOOK_SECRET', 'BAPC_NOTIFICATIONS_KEY']) names.add(n);
  if (optional.warehouse) names.add('WAREHOUSE_SIGNING_SECRET');
  if (optional.agents) { names.add('RELAY_AGENT_TOKEN'); names.add('EGRESS_AGENT_TOKEN'); }
  return [...names].map((n) => `${st.vault}/${n}`);
}
