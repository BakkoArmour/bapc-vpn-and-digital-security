#!/usr/bin/env node
// Ships one BAPC VPN build to BAPC App Hosting (host.bapc.app):
//
//   node deploy/hosting/release.mjs --stage staging|production --digest sha256:... --release <git sha> \
//        [--settings /etc/bapc-vpn/hosting-<stage>.json] [--project prj_...] [--timeout 1800]
//
// Credentials (environment): HOST_CLIENT_ID / HOST_CLIENT_SECRET, a BAPC Login client of app bapc-vpn with audience
// bapc-host and scopes host:read host:deploy host:manage (manage only to register missing apps; its tokens reach
// only the bapc-vpn project).
// Settings file (not secret): { "project_id": "prj_...", "node": "bapc-vpn", "optional": {...}, "publicEnv": {...} }.
//
// 1. Makes any missing App Hosting apps (one per service, all from registry.bapc.app/bapc-vpn/core).
// 2. Submits a revision of each spec (same spec = same revision, so re-running is harmless).
// 3. Deploys vpn-api first (it runs the migrations) and waits until it is ready, then the other eight together.
//    Production waits for the owner's approval in the App Hosting console (tokens can never approve); the script
//    prints where. A failed rollout is rolled back by App Hosting itself: the previous revision keeps serving.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { vpnApps } from './apps.mjs';

export const REPOSITORY = 'bapc-vpn/core';
const DONE = new Set(['ready', 'failed', 'rolled_back', 'rejected', 'cancelled', 'superseded']);

export function client({ url, token, fetchFn = fetch }) {
  return async (method, path, body) => {
    const headers = { authorization: `Bearer ${token}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (method === 'POST') headers['idempotency-key'] = randomUUID();
    const r = await fetchFn(`${url}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 300) }; }
    if (!r.ok && !(r.status === 422 && json.deployment)) throw new Error(`${method} ${path} answered ${r.status}: ${text.slice(0, 300)}`);
    return json;
  };
}

export async function serviceToken({ id, secret, fetchFn = fetch, tokenUrl = 'https://bapc.app/oauth/token' }) {
  const r = await fetchFn(tokenUrl, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret, audience: 'bapc-host', scope: 'host:read host:deploy host:manage' }) });
  if (!r.ok) throw new Error(`BAPC Login answered ${r.status}`);
  return (await r.json()).access_token;
}

/** Waits for one deployment to finish; says once if it waits for approval. */
export async function waitFor(api, dep, { log, origin, timeoutMs, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = Date.now }) {
  const end = now() + timeoutMs;
  let told = false;
  for (;;) {
    const d = (await api('GET', `/v1/deployments/${dep.id}`)).deployment;
    if (d.state === 'awaiting_approval' && !told) { log(`${dep.slug}: waiting for approval at ${origin}/approvals`); told = true; }
    if (DONE.has(d.state)) return d;
    if (now() > end) throw new Error(`${dep.slug}: still ${d.state} after the time limit (App Hosting keeps working on it; check ${origin})`);
    await sleep(5000);
  }
}

export async function release({ api, origin, stage, digest, releaseId, settings, log = console.log, timeoutMs = 30 * 60_000, sleep }) {
  const apps = vpnApps({ digest, stage, release: releaseId, node: settings.node ?? 'bapc-vpn', optional: settings.optional, publicEnv: settings.publicEnv });
  const existing = new Map(((await api('GET', `/v1/apps?project_id=${encodeURIComponent(settings.project_id)}`)).apps ?? []).map((a) => [a.slug, a]));
  const ids = new Map();
  for (const a of apps) {
    let app = existing.get(a.slug);
    if (!app) { app = (await api('POST', '/v1/apps', { project_id: settings.project_id, slug: a.slug, name: a.name, workload_type: a.workload, repository: REPOSITORY })).app; log(`made app ${a.slug}`); }
    if (app.workload_type !== a.workload) throw new Error(`${a.slug} is a ${app.workload_type} app in App Hosting, expected ${a.workload}`);
    ids.set(a.slug, app.id);
  }
  const ship = async (a) => {
    const rev = await api('POST', `/v1/apps/${ids.get(a.slug)}/revisions`, { spec: a.spec, provenance: { commit: releaseId, source: 'deploy/hosting/release.mjs' } });
    if (rev.admission?.decision === 'deny') throw new Error(`${a.slug}: revision refused: ${rev.admission.checks.filter((c) => !c.ok && c.level === 'block').map((c) => c.message).join(' ')}`);
    const r = await api('POST', `/v1/apps/${ids.get(a.slug)}/deployments`, { environment: stage, revision_id: rev.revision.id, reason: `BAPC VPN release ${releaseId}` });
    if (r.deployment.state === 'rejected') throw new Error(`${a.slug}: deployment refused: ${r.deployment.state_reason}`);
    log(`${a.slug}: revision ${rev.revision.seq}, deployment ${r.deployment.id} (${r.deployment.state})`);
    const d = await waitFor(api, { id: r.deployment.id, slug: a.slug }, { log, origin, timeoutMs, sleep });
    if (d.state !== 'ready') throw new Error(`${a.slug}: ${d.state}${d.state_reason ? `: ${d.state_reason}` : ''}`);
    log(`${a.slug}: ready`);
    return d;
  };
  const [first, ...rest] = apps;
  await ship(first);   // vpn-api: migrations first, then everything else
  const results = await Promise.allSettled(rest.map(ship));
  const failed = results.flatMap((r) => (r.status === 'rejected' ? [String(r.reason?.message ?? r.reason)] : []));
  if (failed.length) throw new Error(`release ${releaseId} on ${stage}: ${failed.length} of ${rest.length + 1} failed:\n  ${failed.join('\n  ')}`);
  log(`released ${releaseId} on ${stage}: all ${apps.length} services ready`);
}

function arg(name, dflt) { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; }
async function main() {
  const stage = arg('stage'), digest = arg('digest'), releaseId = arg('release');
  if (!['staging', 'production'].includes(stage) || !digest || !releaseId) throw new Error('usage: release.mjs --stage staging|production --digest sha256:... --release <sha> [--settings file]');
  const settings = JSON.parse(readFileSync(arg('settings', `/etc/bapc-vpn/hosting-${stage}.json`), 'utf8'));
  if (arg('project')) settings.project_id = arg('project');
  if (!settings.project_id) throw new Error('settings need project_id (App Hosting project of BAPC VPN)');
  const origin = String(arg('url', 'https://host.bapc.app')).replace(/\/+$/, '');
  const token = await serviceToken({ id: process.env.HOST_CLIENT_ID ?? '', secret: process.env.HOST_CLIENT_SECRET ?? '' });
  await release({ api: client({ url: origin, token }), origin, stage, digest, releaseId, settings, timeoutMs: Number(arg('timeout', '1800')) * 1000 });
}
if (process.argv[1]?.endsWith('release.mjs')) main().catch((e) => { console.error(e.message); process.exit(1); });
