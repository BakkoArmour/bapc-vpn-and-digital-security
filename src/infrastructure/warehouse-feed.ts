import {createHash, createHmac} from "node:crypto";

// Daily usage totals to the BAPC Data Warehouse (warehouse.bapc.app, read by BAPC Analytics): activity.daily
// events, one per count per UTC day, for app id bapc-vpn. Totals only, never who did what (the Warehouse's
// "activity" dataset forbids personal usage records). Event ids are derived from (app, day, type), so sending
// a day again is recorded once as a duplicate, never double-counted.
// Env: WAREHOUSE_URL, WAREHOUSE_SOURCE_ID (uuid), WAREHOUSE_SIGNING_SECRET. Missing = the feed is off.

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}
export interface DailyActivity {day:string;active_users:number;signups:number;sign_ins:number;onboarded:number;}

const T="bapc_security_core";
export const APP_ID="bapc-vpn";

// A day's totals. day = "YYYY-MM-DD" (UTC).
export const dailyActivity=async(db:PgQueryable,day:string):Promise<DailyActivity>=>{
  const r=await db.query(`
    WITH d AS (SELECT $1::date AS d0, ($1::date + 1) AS d1),
    first_sign_in AS (SELECT account_id, min(at) AS first_at FROM ${T}.portal_audit WHERE action='auth.signed_in' AND account_id NOT LIKE 'erased:%' GROUP BY account_id),
    first_device AS (SELECT account_id, min(created_at) AS first_at FROM ${T}.customer_devices WHERE account_id NOT LIKE 'erased:%' GROUP BY account_id)
    SELECT
      (SELECT count(DISTINCT account_id) FROM ${T}.customer_devices WHERE removed_at IS NULL AND NOT suspended AND created_at < (SELECT d1 FROM d))::int AS active_users,
      (SELECT count(*) FROM first_sign_in WHERE first_at >= (SELECT d0 FROM d) AND first_at < (SELECT d1 FROM d))::int AS signups,
      (SELECT count(*) FROM ${T}.portal_audit WHERE action='auth.signed_in' AND at >= (SELECT d0 FROM d) AND at < (SELECT d1 FROM d))::int AS sign_ins,
      (SELECT count(*) FROM first_device WHERE first_at >= (SELECT d0 FROM d) AND first_at < (SELECT d1 FROM d))::int AS onboarded`,[day]);
  const x=r.rows[0]??{};
  return {day,active_users:Number(x.active_users??0),signups:Number(x.signups??0),sign_ins:Number(x.sign_ins??0),onboarded:Number(x.onboarded??0)};
};

// A stable UUID (v5-shaped) for one count on one day, so a resend is a duplicate.
const stableId=(...parts:string[])=>{
  const h=createHash("sha256").update(parts.join("|")).digest("hex");
  return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-${((parseInt(h[16]!,16)&3)|8).toString(16)}${h.slice(17,20)}-${h.slice(20,32)}`;
};

export const activityEvents=(sourceId:string,a:DailyActivity)=>
  (["active_users","signups","sign_ins","onboarded"] as const).map(type=>({
    event_id:stableId(APP_ID,a.day,type),version:1,source:sourceId,tenant:"bapc",app_id:APP_ID,type:"activity.daily",
    occurred_at:`${a.day}T23:59:59Z`,classification:"internal",payload:{activity_type:type,count:a[type]}
  }));

export const warehouseSignature=(secret:string,t:number,raw:string)=>`t=${t},v1=${createHmac("sha256",secret).update(`${t}.${raw}`).digest("hex")}`;

export interface WarehouseConfig {url:string;sourceId:string;secret:string;}
export const warehouseConfig=(env:NodeJS.ProcessEnv=process.env):WarehouseConfig|null=>{
  const url=env.WAREHOUSE_URL?.replace(/\/$/,""),sourceId=env.WAREHOUSE_SOURCE_ID,secret=env.WAREHOUSE_SIGNING_SECRET;
  return url&&sourceId&&/^[0-9a-f-]{36}$/i.test(sourceId)&&secret&&secret.length>=32?{url,sourceId,secret}:null;
};

export const sendActivity=async(cfg:WarehouseConfig,a:DailyActivity,fetchImpl:typeof fetch=fetch)=>{
  const raw=JSON.stringify({events:activityEvents(cfg.sourceId,a)});
  const t=Math.floor(Date.now()/1000);
  const r=await fetchImpl(`${cfg.url}/internal/api/v1/warehouse/events`,{
    method:"POST",headers:{"content-type":"application/json","x-bapc-source":cfg.sourceId,"x-bapc-signature":warehouseSignature(cfg.secret,t,raw)},
    body:raw,signal:AbortSignal.timeout(15_000)
  });
  const body=await r.json().catch(()=>({})) as {accepted?:number;duplicates?:number;rejected?:number};
  if(r.status!==202)throw new Error(`warehouse answered ${r.status}`);
  return {accepted:body.accepted??0,duplicates:body.duplicates??0,rejected:body.rejected??0};
};
