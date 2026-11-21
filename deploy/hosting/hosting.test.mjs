// BAPC VPN on BAPC App Hosting: the specs (ports, secrets by reference, database through Cheisgos) and the release
// order (API first, then the rest; a failure is reported, approval waits are announced). Run: npm run test:hosting
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requiredSecrets, vpnApps } from './apps.mjs';
import { release } from './release.mjs';

const D = `sha256:${'b'.repeat(64)}`;

test('specs: nine services from one digest, fixed loopback ports per stage, no secret values anywhere', () => {
  const prod = vpnApps({ digest: D, stage: 'production', release: 'abc1234', node: 'bapc-vpn' });
  assert.deepEqual(prod.map((a) => a.slug), ['vpn-api', 'vpn-portal', 'vpn-grpc', 'vpn-oob', 'vpn-worker', 'vpn-console', 'vpn-dns', 'vpn-relay', 'vpn-egress']);
  const ports = (apps) => Object.fromEntries(apps.map((a) => [a.slug, (a.spec.network.ports ?? []).map((p) => `${p.hostPort}/${p.protocol}`).join()]));
  assert.deepEqual(ports(prod), { 'vpn-api': '8080/tcp', 'vpn-portal': '8095/tcp', 'vpn-grpc': '50051/tcp', 'vpn-oob': '8181/tcp', 'vpn-worker': '', 'vpn-console': '8090/tcp', 'vpn-dns': '5353/udp', 'vpn-relay': '51900/udp', 'vpn-egress': '1080/tcp' });
  const stg = vpnApps({ digest: D, stage: 'staging', release: 'abc1234', node: 'bapc-vpn' });
  assert.equal(ports(stg)['vpn-api'], '18080/tcp');
  assert.equal(ports(stg)['vpn-dns'], '15353/udp');
  for (const a of [...prod, ...stg]) {
    assert.equal(a.spec.artifact.imageDigest, D);
    assert.equal(a.spec.rollout.strategy, 'recreate');
    assert.equal(a.spec.placement.node, 'bapc-vpn');
    for (const s of a.spec.secrets ?? []) assert.match(s.secretRef, /^bapc-vpn-(prod|staging)\/[A-Z0-9_]+$/);
    assert.ok(!JSON.stringify(a.spec.env).match(/postgres:\/\/|SECRET=|PASSWORD/), `${a.slug} env has no secrets`);
  }
  const api = prod[0].spec;
  assert.equal(api.env.PGHOST, 'host.containers.internal');
  assert.equal(api.env.PGSSLMODE, 'no-verify');
  assert.ok(api.runtime.command[2].includes('PGOPTIONS="-c role=bapc_vpn_owner"'));
  assert.ok(api.runtime.command[2].includes('exec node dist/src/runtime/production-server.js'));
  assert.ok(api.secrets.some((s) => s.name === 'PG_MIGRATOR_PASSWORD'));
  assert.equal(prod[7].spec.env.BAPC_CONTROLLER_URL, 'http://vpn-api:8080');   // relay → API by network alias
  assert.ok(!prod[1].spec.secrets.some((s) => s.name === 'BAPC_BILLING_KEY'));   // optional secrets only when they exist
  assert.ok(vpnApps({ digest: D, stage: 'production', release: 'x', node: 'n', optional: { portal: true } })[1].spec.secrets.some((s) => s.name === 'BAPC_BILLING_KEY'));
  assert.throws(() => vpnApps({ digest: 'latest', stage: 'production', release: 'x', node: 'n' }), /digest/);
  assert.ok(requiredSecrets('production').includes('bapc-vpn-prod/PG_VPN_CORE_BAPC_VPN_RW_PASSWORD'));
  assert.ok(requiredSecrets('staging', { agents: true }).includes('bapc-vpn-staging/RELAY_AGENT_TOKEN'));
});

/** A fake App Hosting: apps, revisions and deployments that become ready (or fail) after a few polls. */
function fakeHost({ failSlug, approval = false } = {}) {
  const apps = [{ id: 'app_api', slug: 'vpn-api', workload_type: 'http' }];
  const deps = new Map(), order = [];
  let n = 0;
  const api = async (method, path, body) => {
    if (method === 'GET' && path.startsWith('/v1/apps?')) return { apps };
    if (method === 'POST' && path === '/v1/apps') { const a = { id: `app_${body.slug}`, slug: body.slug, workload_type: body.workload_type }; apps.push(a); return { app: a }; }
    let m;
    if (method === 'POST' && (m = path.match(/^\/v1\/apps\/(.+)\/revisions$/))) return { revision: { id: `rev_${m[1]}`, seq: 1 }, admission: { decision: 'allow', checks: [] } };
    if (method === 'POST' && (m = path.match(/^\/v1\/apps\/(.+)\/deployments$/))) {
      const slug = apps.find((a) => a.id === m[1]).slug;
      order.push(slug);
      const d = { id: `dep_${++n}`, slug, polls: 0, state: approval ? 'awaiting_approval' : 'scheduled' };
      deps.set(d.id, d);
      return { deployment: { id: d.id, state: d.state } };
    }
    if (method === 'GET' && (m = path.match(/^\/v1\/deployments\/(.+)$/))) {
      const d = deps.get(m[1]);
      d.polls++;
      if (d.polls >= 2) d.state = d.slug === failSlug ? 'rolled_back' : 'ready';
      else if (!approval) d.state = 'rolling_out';
      return { deployment: { id: d.id, state: d.state, state_reason: d.state === 'rolled_back' ? 'crash loop; previous revision kept serving' : null } };
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
  return { api, apps, order };
}

const SETTINGS = { project_id: 'prj_vpn', node: 'bapc-vpn' };
const quiet = () => {};
const noSleep = async () => {};

test('release: registers missing apps, ships the API first and waits for it, then the other eight', async () => {
  const h = fakeHost();
  const lines = [];
  await release({ api: h.api, origin: 'https://host.bapc.app', stage: 'staging', digest: D, releaseId: 'abc1234', settings: SETTINGS, log: (l) => lines.push(l), sleep: noSleep });
  assert.equal(h.apps.length, 9);
  assert.equal(h.order[0], 'vpn-api');
  assert.equal(h.order.length, 9);
  assert.match(lines.at(-1), /all 9 services ready/);
});

test('release: production announces the approval wait; a rolled-back service fails the release with the reason', async () => {
  const h = fakeHost({ approval: true });
  const lines = [];
  await release({ api: h.api, origin: 'https://host.bapc.app', stage: 'production', digest: D, releaseId: 'abc1234', settings: SETTINGS, log: (l) => lines.push(l), sleep: noSleep });
  assert.ok(lines.some((l) => /vpn-api: waiting for approval at https:\/\/host\.bapc\.app\/approvals/.test(l)));
  const bad = fakeHost({ failSlug: 'vpn-dns' });
  await assert.rejects(release({ api: bad.api, origin: 'o', stage: 'staging', digest: D, releaseId: 'abc1234', settings: SETTINGS, log: quiet, sleep: noSleep }), /1 of 9 failed:\n {2}vpn-dns: rolled_back: crash loop/);
  const apiFails = fakeHost({ failSlug: 'vpn-api' });
  await assert.rejects(release({ api: apiFails.api, origin: 'o', stage: 'staging', digest: D, releaseId: 'abc1234', settings: SETTINGS, log: quiet, sleep: noSleep }), /vpn-api: rolled_back/);
  assert.deepEqual(apiFails.order, ['vpn-api']);   // nothing else is shipped when the API (migrations) fails
});
