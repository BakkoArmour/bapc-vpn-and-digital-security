#!/usr/bin/env node
// Mints a bearer token HmacBearerGuard (src/api/rest/guard.ts) accepts.
//
// Nothing in this repository could actually produce a token before this:
// HmacBearerGuard only verified one, and docs/OPERATIONS-MANUAL.md talks
// about "minting a bearer token" without anywhere that does it. Every role
// (security-read, security-approver, security-owner, security-agent) this
// control plane checks is only reachable with a token this script (or
// HmacBearerGuard.mint, which it calls) produces.
//
// Usage:
//   node scripts/mint-token.mjs --roles security-read,security-approver
//   node scripts/mint-token.mjs --sub 11111111-1111-1111-1111-111111111111 --roles security-agent --ttl 86400
//   CONTROL_API_TOKEN_SECRET=... node scripts/mint-token.mjs --roles security-owner --secret-env CONTROL_API_TOKEN_SECRET
//
// Requires `npm run build` first (imports the compiled guard from dist/).

import {randomUUID} from "node:crypto";
import {existsSync} from "node:fs";
import {HmacBearerGuard} from "../dist/src/api/rest/guard.js";

const UUID_RE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const argOf=(name)=>{
  const i=process.argv.indexOf(`--${name}`);
  return i!==-1?process.argv[i+1]:undefined;
};

if(!existsSync(new URL("../dist/src/api/rest/guard.js",import.meta.url))){
  console.error("dist/src/api/rest/guard.js not found — run `npm run build` first");
  process.exit(1);
}

const secretEnvVar=argOf("secret-env")??"CONTROL_API_TOKEN_SECRET";
const secret=argOf("secret")??process.env[secretEnvVar];
if(!secret){
  console.error(`no secret: pass --secret <value> or set ${secretEnvVar} in the environment (must match the running control plane's CONTROL_API_TOKEN_SECRET)`);
  process.exit(1);
}

const rolesArg=argOf("roles");
if(!rolesArg){
  console.error("--roles is required, comma-separated, e.g. --roles security-read,security-approver");
  process.exit(1);
}
const roles=rolesArg.split(",").map(r=>r.trim()).filter(Boolean);

const sub=argOf("sub")??randomUUID();
if(!UUID_RE.test(sub)){
  console.error(JSON.stringify({
    event:"mint-token.warning",
    warning:"sub is not a UUID — jit_grants and other identity-keyed tables require one; this token will fail on any call that persists a JIT grant under this identity",
    sub
  }));
}

const ttlSeconds=Number(argOf("ttl")??3600);
const exp=Math.floor(Date.now()/1000)+ttlSeconds;

const token=HmacBearerGuard.mint({sub,roles,exp},secret);

console.log(token);
console.error(JSON.stringify({event:"mint-token.issued",sub,roles,expiresAt:new Date(exp*1000).toISOString()}));
