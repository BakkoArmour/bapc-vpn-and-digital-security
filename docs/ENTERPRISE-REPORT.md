# BAPC VPN: Enterprise Standard completion report

22 Nov 2026, after production moved onto BAPC infrastructure (App Hosting + Cheisgos + Secrets + Registry + Backup);
re-checked 07:30 UTC the same day after the security-review fixes; production device CA live 07:55 UTC.
Checked against `bapc-cloud-and-deploy/docs/ENTERPRISE-STANDARD.md`. A box passes only on evidence (Part 2).
**Verdict: not done.** Two sections are Partial; each needs something only the owner can do or approve.

| Section | Pass / Partial / Fail | What's missing | Plan to fix |
|---|---|---|---|
| Accounts, security and access | **Pass** | Nothing. Production signs device certificates with its own CA from BAPC Secrets ("BAPC VPN Device CA 2026", live 22 Nov 07:55 UTC) and refuses the development CA. Owner-approved exceptions apply: R3 (sign-in features live in Sign in with BAPC), R6 (no two-step sign-in), R8 (one-person customer accounts). | — (the old development CA key was deleted from the production database on 22 Nov at the owner's yes) |
| Data, reliability and backups | **Pass** | Nothing required. Worth doing: a point-in-time restore rehearsal on the Cheisgos cluster (the nightly logical backup is restore-tested every night already). | Run the Cheisgos Recovery rehearsal into an isolated copy. |
| Payments and commerce | **Partial** | 1. A real purchase and refund has never been run end to end on the live site. 2. EU/UK consumer VAT: registration not done, so Billing rule 6 is deployed but switched off. | 1. Owner buys and refunds a plan (5 minutes). 2. Register for EU OSS and UK VAT, enter the numbers in Billing and Stripe, switch rule 6 on. |
| Quality | **Pass** | Nothing required. Live accessibility check on 22 Nov (below) found one heading-order issue, fixed in 85a30df. A person-run NVDA or VoiceOver pass is still worth doing. | — |
| Operations | **Partial** | Error tracking does not alert yet. The VPN is wired to BAPC Observability (it only needs `OBOP_SYSTEM_ID` and `OBOP_INGEST_TOKEN`), but the token can't be issued: the saved Observability owner database password is out of date, and the VPN's official BAPC number for its slot is not recorded anywhere (the tooling says never guess it). Errors are in the server journal until then. | Owner: give the VPN's number (an infrastructure number 1 to 60, or the next app number, 102) and a current Observability owner connection string; then `connect-app` issues the token, it goes into BAPC Secrets `bapc-vpn-prod`, and a release turns alerts on. |

## Evidence (22 Nov 2026)

**Accounts, security and access**
- Sign up, sign in, sign out, reset and verification through Sign in with BAPC; vpn.bapc.app/auth/start hands off to bapc.app with PKCE.
- Staff admin area (vpn.bapc.app/admin) for bapc.app admins only (404 for everyone else), enforced on the server; owner confirmed it works.
- Customer data is separated per account; every action is in `portal_audit`, and staff actions are audited as `staff`.
- Secrets live in BAPC Secrets (`bapc-vpn-prod`), delivered to containers as Podman secrets; none are in code, images or command lines.
- Each stage's services read only their own BAPC Secrets environment (App Hosting refuses others), run on their own network, and get per-deployment secret names. Each Cheisgos cluster sees only its own backups, passphrase and superuser password (both stored in BAPC Secrets). Device CA: own CA per stage from BAPC Secrets, only the API, portal and gRPC receive it (checked in the running containers); the only certificate the development CA issued expired on 17 Oct.
- HTTPS only, secure cookies, CSRF checks; rate limits on sign-in and public endpoints.
- Privacy policy, terms and cookie notice are on the site; account page offers Download my data and Close my account.

**Data, reliability and backups**
- PostgreSQL 18.7 on BAPC Cheisgos (`vpn-core`): primary plus streaming standby, TLS, encrypted storage. Apps use the stable write endpoint 127.0.0.1:55432, which follows the primary on failover.
- 25 tracked migrations (024: least-privilege maintenance functions; 025: limits on them). The services run as a rows-only role, and a database restart or failover no longer stops them (5ff9c46: a lost connection is logged and replaced; production restart measured at 2 s).
- Nightly backup at 03:15 UTC: dump, full test restore on the same PostgreSQL version with table/migration counts compared, encrypted, sent to BAPC Backup. Verified tonight. Cheisgos also archives WAL and sends an encrypted pgBackRest set to BAPC Backup nightly (03:40 UTC), first copy verified.
- Staging (staging-vpn.bapc.app) and production run separately: their own databases, secrets and ports. Development runs locally.

**Payments and commerce**
- BAPC Billing on Stripe: Monthly $8.99 and Yearly $35.88, both with a 7-day free trial; upgrades, downgrades and cancellations; invoices and receipts from Billing; the signed `plan.changed` hook pauses or resumes devices at once.
- US tax handled (Ohio business-use rule). EU/UK VAT built and deployed but off until registration.
- Transactional email through BAPC Notifications (test email arrived).

**Quality**
- 398 unit tests (390 pass, 8 skipped, 0 fail), plus hosting tests (4), App Hosting (40), Cheisgos (85), Billing and Backup suites.
- No placeholder wording: "coming soon" texts for the optional AWS integrations and the sign-in fallback replaced with plain messages (e609259).
- Public pages load in 0.2–0.45 s. No dead links on the public pages (crawl, 22 Nov).
- Works on phone, tablet and desktop.
- Accessibility, checked live on 22 Nov on the home, help, privacy, terms, account (signed in), admin and admin account pages: every page has a language, one h1, a main landmark and a skip link; every form field has a label and every link and button a name; no positive tab order; every focusable element shows a focus ring; all text measured at WCAG AA contrast or better (297 text elements). One finding: the home page went from h1 to h3; fixed in 85a30df (a section heading for screen readers), live on production 22 Nov.

**Operations**
- Uptime: BAPC Status checks `vpn` and `vpn-control` every 5 minutes (both up; 7-day uptime 97.7% and 98.5%, including tonight's switch-over windows).
- Logs: structured JSON from every container in the server journal.
- Analytics: daily usage totals to the Warehouse (confirmed sent tonight).
- Hosting: BAPC App Hosting on vpn.bapc.app and vpn.bapc-headquarters.com.
- One-step release with rollback: `deploy/hosting/build-image.sh` then `release.mjs`; App Hosting rolls a failed rollout back on its own. Releases today: 9dbaf68, 5ff9c46, e609259 (production; staging first each time). App Hosting 1bb9806 removes the old container before starting the new one: the e609259 release paused the WireGuard gateway sync for one 10-second retry instead of a minute.
- Admin dashboard: vpn.bapc.app/admin. Support: BAPC Help Desk (support.bapc.app).
- Documentation: `docs/PRODUCTION.md`, `deploy/hosting/README.md`, user help at vpn.bapc.app/help.

## Also open (not Enterprise Standard items)

- bapc.app's directory still lists BAPC VPN as "dev" with no address, so visitors can't find it and the outside audit scan skips it. Listing it is a public launch decision for the owner.
- The stopped Docker stack is kept as a fallback; remove it after a quiet week, with the owner's yes.
- Merge the Code Adytum branches: `vpn/launch-readiness`, `host-vpn-ready`, `sql-vault-link`, `backup-bapc-vpn`, `billing-eu-uk-vat`, `vpn-feed`, `status-bapc-vpn`.
- A pen test. Stronger later: a signing service in BAPC Secrets so the device CA key never leaves it (today it is held in BAPC Secrets and loaded into memory).
- App Hosting: per-host outbound allowlists are recorded but not enforced (private ranges, loopback and mail are blocked; the public internet is not), and the console says so.
