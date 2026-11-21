import test from "node:test";
import assert from "node:assert/strict";
import {createHmac, randomUUID, createHash} from "node:crypto";
import {fileURLToPath} from "node:url";
import {errorFromLogLine} from "../../../src/infrastructure/error-reporting.js";
import {buildErrorEvent, scrub} from "../../../src/infrastructure/obop-errors.js";
import {activityEvents, dailyActivity, sendActivity, warehouseConfig, warehouseSignature} from "../../../src/infrastructure/warehouse-feed.js";

// Monitoring: which log lines become Observability errors, what they look like on the wire, and the daily
// usage totals sent to the BAPC Data Warehouse.

test("only error log lines are reported to Observability, with their fields as attributes",()=>{
  const e=errorFromLogLine('{"event":"portal.payment_check_failed","accountId":"acct-1","error":"BAPC Billing answered 502"}');
  assert.deepEqual(e,{event:"portal.payment_check_failed",message:"BAPC Billing answered 502",attributes:{"log.accountId":"acct-1"}});
  assert.equal(errorFromLogLine('{"event":"ready","service":"x"}'),null,"normal events aren't errors");
  assert.equal(errorFromLogLine("plain text"),null);
  assert.equal(errorFromLogLine("{not json"),null);
  assert.equal(errorFromLogLine('{"event":"outbox.flush_failed"}')?.message,"outbox.flush_failed","an event name that says failed counts");
});

test("the Observability event is a scrubbed high-severity log.record scoped to this app",()=>{
  const env={OBOP_INGEST_TOKEN:`obop.${randomUUID()}.${"s".repeat(40)}`,OBOP_SYSTEM_ID:"bapc-sys-106"};
  const built=buildErrorEvent(env,new Error("Billing failed for pat@example.com with Bearer abc.def"),{route:"portal.payment_check_failed",attributes:{"app.process":"customer-portal"}});
  const ev=built!.body.events[0] as Record<string,any>;
  assert.equal(ev.eventType,"log.record");assert.equal(ev.severity,"high");assert.equal(ev.systemId,"bapc-sys-106");assert.equal(ev.serviceKey,"web");
  assert.doesNotMatch(ev.message,/pat@example\.com|abc\.def/,"emails and tokens never leave the server");
  assert.equal(ev.attributes["app.process"],"customer-portal");
  assert.equal(buildErrorEvent({},new Error("x")),undefined,"not connected = nothing sent");
  assert.equal(scrub("api_key=sk_live_123456"),"api_key=[redacted]");
});

test("daily usage events are totals only, stable per day, and signed the way the Warehouse checks",async()=>{
  const sourceId=randomUUID();
  const a={day:"2026-11-20",active_users:3,signups:2,sign_ins:5,onboarded:1};
  const evs=activityEvents(sourceId,a);
  assert.deepEqual(evs.map(e=>[e.payload.activity_type,e.payload.count]),[["active_users",3],["signups",2],["sign_ins",5],["onboarded",1]]);
  assert.ok(evs.every(e=>e.app_id==="bapc-vpn"&&e.type==="activity.daily"&&e.source===sourceId&&e.classification==="internal"&&/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(e.event_id)));
  assert.deepEqual(activityEvents(sourceId,a).map(e=>e.event_id),evs.map(e=>e.event_id),"resending a day reuses the ids (a duplicate, not a double count)");
  assert.equal(new Set(evs.map(e=>e.event_id)).size,4);
  assert.ok(!JSON.stringify(evs).includes("@"),"no personal data");
  assert.equal(warehouseSignature("k",100,"{}"),`t=100,v1=${createHmac("sha256","k").update("100.{}").digest("hex")}`);
  let seen:{url:string;headers:Record<string,string>;body:string}|null=null;
  const cfg={url:"https://warehouse.example",sourceId,secret:"w".repeat(40)};
  const r=await sendActivity(cfg,a,(async(u:string,init?:RequestInit)=>{seen={url:u,headers:init!.headers as Record<string,string>,body:String(init!.body)};return Response.json({accepted:4,duplicates:0,rejected:0},{status:202});}) as typeof fetch);
  assert.deepEqual(r,{accepted:4,duplicates:0,rejected:0});
  assert.equal(seen!.url,"https://warehouse.example/internal/api/v1/warehouse/events");
  assert.equal(seen!.headers["x-bapc-source"],sourceId);
  const t=Number(seen!.headers["x-bapc-signature"]!.match(/^t=(\d+),/)![1]);
  assert.equal(seen!.headers["x-bapc-signature"],warehouseSignature(cfg.secret,t,seen!.body));
  await assert.rejects(sendActivity(cfg,a,(async()=>new Response("{}",{status:401})) as typeof fetch),/401/);
  assert.equal(warehouseConfig({}),null,"no settings = feed off");
  assert.equal(warehouseConfig({WAREHOUSE_URL:"https://w",WAREHOUSE_SOURCE_ID:"not-a-uuid",WAREHOUSE_SIGNING_SECRET:"x".repeat(40)}),null);
});

const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: daily usage totals count the right day from real portal data",{skip:!liveDatabaseUrl},async()=>{
  const {Postgres}=await import("../../../src/infrastructure/postgres/client.js");
  const {MigrationRunner,loadMigrations}=await import("../../../src/infrastructure/postgres/migrate.js");
  const {PgRepositories}=await import("../../../src/infrastructure/postgres/repositories.js");
  const db=new Postgres(liveDatabaseUrl!);
  await new MigrationRunner(db).apply(loadMigrations(fileURLToPath(new URL("../../../../db",import.meta.url))));
  const acct=`acct-${randomUUID()}`,deviceId=randomUUID(),nodeId=randomUUID(),day="2031-05-04";
  try{
    const before=await dailyActivity(db,day);
    const repo=new PgRepositories(db),now=new Date();
    await repo.save({id:deviceId,hostname:"h",hardwareId:`hw-${deviceId}`,platform:"linux" as const,osVersion:"1",compromised:false,revoked:false,
      posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:now},createdAt:now,updatedAt:now});
    await repo.save({id:nodeId,deviceId,wireGuardPublicKey:`pk-${nodeId}`.slice(0,60),internalIpv4:`10.198.${Math.floor(Math.random()*250)+2}.${Math.floor(Math.random()*250)+2}`,internalIpv6:`fd98::${randomUUID().slice(0,4)}`,
      listenPort:51820,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});
    await db.query(`INSERT INTO bapc_security_core.customer_devices(node_id,account_id,email,name,kind,created_at) VALUES($1,$2,'p@example.com','Phone','android',$3)`,[nodeId,acct,`${day}T10:00:00Z`]);
    for(const at of [`${day}T09:00:00Z`,`${day}T18:00:00Z`])
      await db.query(`INSERT INTO bapc_security_core.portal_audit(account_id,actor,action,at) VALUES($1,'customer','auth.signed_in',$2)`,[acct,at]);
    const after=await dailyActivity(db,day);
    assert.equal(after.signups-before.signups,1);
    assert.equal(after.sign_ins-before.sign_ins,2);
    assert.equal(after.onboarded-before.onboarded,1);
    assert.ok(after.active_users>=1);
    assert.equal((await dailyActivity(db,"2031-05-05")).signups,0,"counted on its own day only");
  }finally{
    await db.query(`DELETE FROM bapc_security_core.portal_audit WHERE account_id=$1`,[acct]);
    await db.query(`DELETE FROM bapc_security_core.customer_devices WHERE node_id=$1`,[nodeId]);
    await db.query(`DELETE FROM bapc_security_core.mesh_nodes WHERE node_id=$1`,[nodeId]);
    await db.query(`DELETE FROM bapc_security_core.devices WHERE device_id=$1`,[deviceId]);
    await db.close();
  }
});
