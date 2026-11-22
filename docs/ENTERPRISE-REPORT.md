# BAPC VPN: Enterprise Standard completion report

22 Nov 2026, after production moved onto BAPC infrastructure (App Hosting + Cheisgos + Secrets + Registry + Backup).
Checked against `bapc-cloud-and-deploy/docs/ENTERPRISE-STANDARD.md`. A box passes only on evidence (Part 2).
**Verdict: not done.** Three sections are Partial; each needs something only the owner can do or approve.

| Section | Pass / Partial / Fail | What's missing | Plan to fix |
|---|---|---|---|
| Accounts, security and access | **Pass** | Nothing. Owner-approved exceptions apply: R3 (sign-in features live in Sign in with BAPC), R6 (no two-step sign-in), R8 (one-person customer accounts). | — |
| Data, reliability and backups | **Pass** | Nothing required. Worth doing: a point-in-time restore rehearsal on the Cheisgos cluster (the nightly logical backup is restore-tested every night already). | Run the Cheisgos Recovery rehearsal into an isolated copy. |
| Payments and commerce | **Partial** | 1. A real purchase and refund has never been run end to end on the live site. 2. EU/UK consumer VAT: registration not done, so Billing rule 6 is deployed but switched off. | 1. Owner buys and refunds a plan (5 minutes). 2. Register for EU OSS and UK VAT, enter the numbers in Billing and Stripe, switch rule 6 on. |
| Quality | **Partial** | A person-run screen-reader pass (WCAG AA). Automated accessibility checks pass. | Owner or a tester walks sign-up, account and admin with NVDA or VoiceOver. |
| Operations | **Partial** | Error tracking does not alert yet: BAPC Observability needs its ingest token (`OBOP_INGEST_TOKEN`, `OBOP_SYSTEM_ID`); until then errors are only in the server journal. | Owner issues the token; store it in BAPC Secrets `bapc-vpn-prod` and redeploy (the services already read it). |

## Evidence (22 Nov 2026)

**Accounts, security and access**
- Sign up, sign in, sign out, reset and verification through Sign in with BAPC; vpn.bapc.app/auth/start hands off to bapc.app with PKCE.
- Staff admin area (vpn.bapc.app/admin) for bapc.app admins only (404 for everyone else), enforced on the server; owner confirmed it works.
- Customer data is separated per account; every action is in `portal_audit`, and staff actions are audited as `staff`.
- Secrets live in BAPC Secrets (`bapc-vpn-prod`), delivered to containers as Podman secrets; none are in code, images or command lines.
- HTTPS only, secure cookies, CSRF checks; rate limits on sign-in and public endpoints.
- Privacy policy, terms and cookie notice are on the site; account page offers Download my data and Close my account.

**Data, reliability and backups**
- PostgreSQL 18.7 on BAPC Cheisgos (`vpn-core`): primary plus streaming standby, TLS, encrypted storage. Apps use the stable write endpoint 127.0.0.1:55432, which follows the primary on failover.
- 24 tracked migrations (024 added tonight: least-privilege maintenance functions). The services run as a rows-only role.
- Nightly backup at 03:15 UTC: dump, full test restore on the same PostgreSQL version with table/migration counts compared, encrypted, sent to BAPC Backup. Verified tonight. Cheisgos also archives WAL and sends an encrypted pgBackRest set to BAPC Backup nightly (03:40 UTC), first copy verified.
- Staging (staging-vpn.bapc.app) and production run separately: their own databases, secrets and ports. Development runs locally.

**Payments and commerce**
- BAPC Billing on Stripe: Monthly $8.99 and Yearly $35.88, both with a 7-day free trial; upgrades, downgrades and cancellations; invoices and receipts from Billing; the signed `plan.changed` hook pauses or resumes devices at once.
- US tax handled (Ohio business-use rule). EU/UK VAT built and deployed but off until registration.
- Transactional email through BAPC Notifications (test email arrived).

**Quality**
- 386 unit tests pass, plus hosting tests (4), App Hosting (38), Cheisgos (81), Billing and Backup suites.
- Public pages load in 0.2–0.45 s. No dead links on the public pages (crawl, 22 Nov).
- Works on phone, tablet and desktop; automated accessibility checks pass.

**Operations**
- Uptime: BAPC Status checks `vpn` and `vpn-control` every 5 minutes (both up; 7-day uptime 97.7% and 98.5%, including tonight's switch-over windows).
- Logs: structured JSON from every container in the server journal.
- Analytics: daily usage totals to the Warehouse (confirmed sent tonight).
- Hosting: BAPC App Hosting on vpn.bapc.app and vpn.bapc-headquarters.com.
- One-step release with rollback: `deploy/hosting/build-image.sh` then `release.mjs`; App Hosting rolls a failed rollout back on its own. `cutover.sh` fell back to Docker automatically three times tonight.
- Admin dashboard: vpn.bapc.app/admin. Support: BAPC Help Desk (support.bapc.app).
- Documentation: `docs/PRODUCTION.md`, `deploy/hosting/README.md`, user help at vpn.bapc.app/help.

## Also open (not Enterprise Standard items)

- bapc.app's directory still lists BAPC VPN as "dev" with no address, so visitors can't find it and the outside audit scan skips it. Listing it is a public launch decision for the owner.
- The stopped Docker stack is kept as a fallback; remove it after a quiet week, with the owner's yes.
- Merge the Code Adytum branches: `vpn/launch-readiness`, `host-vpn-ready`, `sql-vault-link`, `backup-bapc-vpn`, `billing-eu-uk-vat`, `vpn-feed`, `status-bapc-vpn`.
- A pen test, and keys in a hardware-backed store (Trust Core signs with a development CA held in PostgreSQL).
