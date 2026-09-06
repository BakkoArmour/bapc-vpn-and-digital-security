#!/usr/bin/env node
// A self-audit of THIS REPOSITORY only — it checks what can be checked
// statically/locally (build, tests, secret hygiene, migration ordering,
// dependency vulnerabilities) and prints, separately and explicitly, the much
// longer list of acceptance gates from the Production Completion Addendum
// that require a live deployment, physical hardware, or a third party and
// therefore CANNOT be verified by running a script in this checkout.
//
// A clean run of this script is necessary, not sufficient, for the
// "BAPC Universal Final Audit" the build documents describe.

import {execSync} from "node:child_process";
import {readdirSync, readFileSync, existsSync} from "node:fs";
import {join} from "node:path";

const results = [];
const check = (name, fn) => {
  try {
    const detail = fn();
    results.push({name, pass: true, detail: detail ?? ""});
  } catch (err) {
    results.push({name, pass: false, detail: err.message ?? String(err) });
  }
};
const run = (cmd) => execSync(cmd, {stdio: ["ignore", "pipe", "pipe"], encoding: "utf8"});

check("TypeScript strict build", () => { run("npm run build"); return "tsc -p tsconfig.json exited 0"; });

check("Automated test suite", () => {
  const out = run("npm test");
  const match = out.match(/ℹ pass (\d+)/);
  const fail = out.match(/ℹ fail (\d+)/);
  if (fail && Number(fail[1]) > 0) throw new Error(`${fail[1]} test(s) failed`);
  return `${match?.[1] ?? "?"} tests passed`;
});

check("Dependency vulnerability scan (npm audit, prod deps)", () => {
  try {
    run("npm audit --omit=dev --audit-level=high");
    return "no high/critical vulnerabilities in production dependencies";
  } catch (err) {
    throw new Error("npm audit reported high/critical findings — see `npm audit` output");
  }
});

check("Dependencies are locked", () => {
  if (!existsSync("package-lock.json")) throw new Error("package-lock.json is missing");
  return "package-lock.json present";
});

check("No private key material committed", () => {
  const skip = new Set(["node_modules", "dist", ".git", "docs"]);
  const hits = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, {withFileTypes: true})) {
      if (skip.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!/\.(ts|js|json|env|pem|key)$/.test(entry.name)) continue;
      if (entry.name === ".env.example") continue;
      const text = readFileSync(full, "utf8");
      if (/-----BEGIN (RSA |EC )?PRIVATE KEY-----/.test(text)) hits.push(full);
    }
  };
  walk(".");
  if (hits.length) throw new Error(`private key material found in: ${hits.join(", ")}`);
  return "no PEM private key blocks found outside docs/";
});

check(".env is not committed", () => {
  const tracked = run("git ls-files").split("\n");
  if (tracked.includes(".env")) throw new Error(".env is tracked by git");
  return ".env is not tracked (only .env.example is)";
});

check("Database migrations are sequentially numbered with no gaps", () => {
  const files = readdirSync("db").filter(f => f.endsWith(".sql")).sort();
  const numbers = files.map(f => Number(f.match(/^(\d+)_/)?.[1]));
  if (numbers.some(Number.isNaN)) throw new Error("a db/*.sql file doesn't start with NNN_");
  for (let i = 1; i < numbers.length; i++) {
    if (numbers[i] !== numbers[i-1] + 1) throw new Error(`gap between ${files[i-1]} and ${files[i]}`);
  }
  return `${files.length} migrations, 001..${String(numbers.at(-1)).padStart(3,"0")}, no gaps`;
});

const failed = results.filter(r => !r.pass);
console.log("BAPC Universal Final Audit — repository self-check\n");
for (const r of results) {
  console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
}

console.log("\nNOT COVERED by this script (requires a live deployment, hardware, or a third party):");
for (const item of [
  "Dual-control root-key ceremony on a real, air-gapped HSM (runbooks/root-ca-ceremony.md) — AWS KMS-backed intermediate signing is real and wired when AWS_KMS_INTERMEDIATE_KEY_ID is set, but that's a single cloud account, not an air-gapped HSM under multi-party physical custody",
  "Native Linux/Windows adapters exercised on a real elevated host with WireGuard/nftables/WFP installed",
  "Apple NetworkExtension client built and signed under an Apple Developer Program account",
  "Signed, notarized/authenticode installers for every platform",
  "Multi-region relay/egress hosting with real fixed IPs and failover drills",
  "Point-in-time database restore rehearsed into an isolated environment",
  "Independent third-party penetration test with no unresolved critical/high findings",
  "Live incident-response, disaster-recovery and on-call rehearsal",
  "BAPC Diagnostics/Headquarters/Cloud-Deployment/Integration sibling apps actually reachable end-to-end",
  "An actual AWS account/secret populated in AWS Secrets Manager (the integration itself is real and wired in src/infrastructure/aws-secrets.ts — set AWS_SECRETS_MANAGER_SECRET_ID once one exists)",
]) console.log(`  - ${item}`);

console.log(`\n${failed.length === 0 ? "All repository-level checks passed." : `${failed.length} repository-level check(s) failed.`} This is a foundation-readiness signal, not a production-complete declaration.`);
process.exit(failed.length === 0 ? 0 : 1);
