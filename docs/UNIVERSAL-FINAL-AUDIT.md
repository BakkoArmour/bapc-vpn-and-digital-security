# BAPC Universal Final Audit

The build documents this repository was reconstructed from define a
"Universal Final Audit" as one of the production acceptance gates: a check
across "routes, authentication, device enrollment, VPN connectivity, policy
enforcement, DNS, relays, OOB recovery, threat response, SOC controls,
mobile/desktop behavior, backups, monitoring, copyright and cleanup of test
accounts/data" performed after live deployment.

That audit needs a live, deployed system to run against. It cannot be
performed by running a script inside this checkout — there is no live
deployment here.

## What `scripts/universal-final-audit.mjs` actually does

`npm run audit:final` runs a **repository self-check**: the subset of that
audit's spirit that *is* verifiable statically —

- the TypeScript strict build succeeds,
- the full automated test suite passes,
- production dependencies have no known high/critical vulnerabilities
  (`npm audit`),
- dependencies are locked (`package-lock.json` present),
- no PEM private-key block is committed anywhere in the source tree,
- `.env` itself is never tracked (only `.env.example`),
- `db/*.sql` migrations are sequentially numbered with no gaps.

A clean run is a genuine, useful signal — it is the "foundation" half of
`docs/build-source/BAPC.Security.Production.Completion.Addendum.docx`'s
own framing ("TESTED FOUNDATION — PRODUCTION COMPLETION IN PROGRESS"). It is
**not** the Universal Final Audit itself, and the script says so in its own
output rather than implying otherwise.

## What still requires a live deployment (or a third party) to check

The script prints this list itself on every run; it is reproduced here for
reference:

- Root/intermediate CA generated on a real HSM under dual control.
- Native Linux/Windows adapters exercised on a real elevated host with
  WireGuard/nftables/WFP actually installed.
- An Apple NetworkExtension client, built and signed under an Apple
  Developer Program account (does not exist in this repository — see
  `native/apple/adapter.ts`).
- Signed, notarized/Authenticode installers for every supported platform.
- Multi-region relay/egress hosting with real fixed IPs and a real failover
  drill.
- A point-in-time database restore, rehearsed into an isolated environment.
- An independent third-party penetration test with no unresolved
  critical/high findings.
- A live incident-response and disaster-recovery on-call rehearsal.
- The BAPC Diagnostics™/Headquarters™/Cloud & Deployment™/Integration™
  sibling applications actually deployed and reachable end-to-end (this
  repository only implements this side of that contract —
  `integrations/signed-event-client.ts` /
  `src/application/integrations.ts`).
- Production secrets issued from a real secret manager, not the
  `.env.example` development defaults.

Do not declare this application "production complete" on the strength of
`npm run audit:final` passing. Use it as a pre-flight check before attempting
the items above, not as a replacement for them.
