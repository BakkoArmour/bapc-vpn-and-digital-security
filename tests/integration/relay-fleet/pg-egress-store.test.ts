import test from "node:test";
import assert from "node:assert/strict";
import {PgEgressStore} from "../../../services/egress/pg-egress-store.js";

// EgressSelector existed fully built and tested with no registry to select
// from at all — db/014_egress_gateways.sql and this store are new.
// Modeled directly on PgRelayStore's already-established pattern.

test("PgEgressStore.insert upserts a gateway with the default max_sessions when none is reported",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.insert("g1","us-east-1","203.0.113.30:1080");
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.egress_gateways/);
  assert.match(queries[0]!.text,/ON CONFLICT\(gateway_id\) DO UPDATE/);
  assert.deepEqual(queries[0]!.values,["g1","us-east-1","203.0.113.30:1080",null]);
});

// A self-registering gateway (src/runtime/egress-server.ts) reports its
// own configured ceiling (EGRESS_MAX_SESSIONS) instead of leaving
// max_sessions at the schema's generic default of 500 forever.
test("PgEgressStore.insert reports a real configured max_sessions when provided",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.insert("g1","us-east-1","203.0.113.30:1080",250);
  assert.deepEqual(queries[0]!.values,["g1","us-east-1","203.0.113.30:1080",250]);
});

test("PgEgressStore.get returns null for an unknown gateway",async()=>{
  const store=new PgEgressStore({query:async()=>({rows:[]})});
  assert.equal(await store.get("missing"),null);
});

test("PgEgressStore.get maps a real row",async()=>{
  const store=new PgEgressStore({query:async()=>({rows:[{gateway_id:"g1",region:"us-east-1",fixed_ip:"203.0.113.30:1080",is_healthy:true,state:"ACTIVE"}]})});
  const row=await store.get("g1");
  assert.deepEqual(row,{gatewayId:"g1",region:"us-east-1",fixedIp:"203.0.113.30:1080",isHealthy:true,state:"ACTIVE"});
});

// load_percent/is_healthy/latency_ms/active_sessions had no write path at
// all before this — a gateway's recorded health was frozen at whatever
// insert() set it to, forever. Real values now come from src/runtime/
// egress-server.ts's actual measurements.
test("PgEgressStore.heartbeat updates health, latency and session count",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.heartbeat("g1",{loadPercent:33,healthy:true,latencyMs:12,activeSessions:7});
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.egress_gateways/);
  assert.deepEqual(queries[0]!.values,["g1",33,true,12,7]);
});

const gatewayRow=(overrides:Record<string,unknown>={})=>({
  gateway_id:"g1",region:"us-east-1",fixed_ip:"203.0.113.30:1080",is_healthy:true,
  load_percent:"5.00",last_heartbeat:new Date().toISOString(),
  latency_ms:8,active_sessions:30,max_sessions:100,...overrides
});

test("PgEgressStore.candidates only returns ACTIVE, recently-heartbeated gateways",async()=>{
  const store=new PgEgressStore({
    query:async(text)=>{
      assert.match(text,/state='ACTIVE'/);
      assert.match(text,/last_heartbeat>now\(\)-interval '30 seconds'/);
      return {rows:[gatewayRow()]};
    }
  });
  const candidates=await store.candidates();
  assert.equal(candidates.length,1);
  assert.equal(candidates[0]!.id,"g1");
  assert.equal(candidates[0]!.loadPercent,5);
  assert.equal(candidates[0]!.latencyMs,8);
  assert.equal(candidates[0]!.activeSessions,30);
});

// capacityPercent is computed from active_sessions/max_sessions at read
// time — 30 of 100 sessions is 30%.
test("PgEgressStore computes capacityPercent from active_sessions/max_sessions at read time",async()=>{
  const store=new PgEgressStore({query:async()=>({rows:[gatewayRow({active_sessions:30,max_sessions:100})]})});
  const [candidate]=await store.candidates();
  assert.equal(candidate!.capacityPercent,30);
});

test("PgEgressStore.remove deletes the gateway",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.remove("g1");
  assert.match(queries[0]!.text,/DELETE FROM bapc_security_core\.egress_gateways/);
});
