// Puts BAPC VPN's plans on sale in BAPC Billing (POST /api/v1/plans with this app's key), from the same PLANS
// the site shows, so the plan ids, prices and free trial can't drift apart. Safe to run again: Billing leaves a
// plan already on sale at the same price as it is (and only updates the trial if it changed); a different price
// for an existing plan id is refused by Billing, never changed silently.
//
// Run where the key lives (the customer-portal container):
//   docker compose exec customer-portal node dist/src/runtime/register-billing-plans.js
// Env: BAPC_BILLING_KEY (required), BAPC_BILLING_URL (default https://billing.bapc.app).
import {BILLING_APP_ID} from "../infrastructure/bapc-accounts.js";
import {PLANS, PLAN_TRIAL_DAYS} from "./portal-pages.js";

const key=process.env.BAPC_BILLING_KEY??"";
const base=process.env.BAPC_BILLING_URL??"https://billing.bapc.app";
if(key.length<32){console.error("BAPC_BILLING_KEY is not set");process.exit(2);}

const plans=PLANS.map(p=>({id:p.id,name:p.name,amount_cents:p.cents,interval:p.interval,trial_days:PLAN_TRIAL_DAYS}));
const r=await fetch(new URL("/api/v1/plans",base),{
  method:"POST",headers:{"content-type":"application/json",authorization:`Bearer ${key}`},
  body:JSON.stringify({app:BILLING_APP_ID,plans}),signal:AbortSignal.timeout(30_000)
});
const body=await r.text();
console.log(JSON.stringify({event:"billing.plans_registered",status:r.status,sent:plans,answer:body.slice(0,1000)}));
if(!r.ok)process.exit(1);
// Read back what Billing now sells, as customers will see it.
const list=await (await fetch(new URL(`/api/v1/plans?app=${BILLING_APP_ID}`,base))).json() as {plans?:{id:string;amount_cents:number;interval:string;trial_days?:number}[]};
console.log(JSON.stringify({event:"billing.plans_on_sale",plans:(list.plans??[]).map(p=>({id:p.id,amount_cents:p.amount_cents,interval:p.interval,trial_days:p.trial_days??0}))}));
