// Registers https://vpn.bapc.app/api/v1/billing/hook with BAPC Billing (POST /api/v1/hook, this app's key), so a
// plan change, failed renewal or cancellation pauses or resumes devices at once instead of at the next 15-minute sync.
// Billing answers a new signing secret once; this prints ONLY "BAPC_BILLING_HOOK_SECRET=<secret>" on stdout so it can
// be piped straight into deploy/.env without anyone seeing it, e.g. on the server:
//   docker compose exec -T customer-portal node dist/src/runtime/register-billing-hook.js > /tmp/hook.env && <upsert into .env>
// Re-running rotates the secret (Billing replaces the old one), so restart customer-portal after updating .env.
// Env: BAPC_BILLING_KEY (required), BAPC_BILLING_URL, PORTAL_PUBLIC_ORIGIN.
import {BILLING_APP_ID} from "../infrastructure/bapc-accounts.js";

const key=process.env.BAPC_BILLING_KEY??"";
const base=process.env.BAPC_BILLING_URL??"https://billing.bapc.app";
const origin=(process.env.PORTAL_PUBLIC_ORIGIN??"https://vpn.bapc.app").replace(/\/$/,"");
if(key.length<32){console.error("BAPC_BILLING_KEY is not set");process.exit(2);}

const r=await fetch(new URL("/api/v1/hook",base),{
  method:"POST",headers:{"content-type":"application/json",authorization:`Bearer ${key}`},
  body:JSON.stringify({app:BILLING_APP_ID,url:`${origin}/api/v1/billing/hook`,events:["plan.changed"]}),signal:AbortSignal.timeout(30_000)
});
const body=await r.json().catch(()=>({})) as {secret?:unknown;hook?:unknown;error?:unknown};
if(!r.ok||typeof body.secret!=="string"||!/^bhk_[0-9a-f]{64}$/.test(body.secret)){
  console.error(JSON.stringify({event:"billing.hook_register_failed",status:r.status,error:body.error??null}));
  process.exit(1);
}
console.error(JSON.stringify({event:"billing.hook_registered",hook:body.hook}));
console.log(`BAPC_BILLING_HOOK_SECRET=${body.secret}`);
