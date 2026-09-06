import test from "node:test";
import assert from "node:assert/strict";
import {PgEgressStore} from "../../../services/egress/pg-egress-store.js";

// EgressSelector existed fully built and tested with no registry to select
// from at all — db/014_egress_gateways.sql and this store are new.
// Modeled directly on PgRelayStore's already-established pattern.

test("PgEgressStore.insert upserts a gateway",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.insert("g1","us-east-1","203.0.113.30:1080");
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.egress_gateways/);
  assert.match(queries[0]!.text,/ON CONFLICT\(gateway_id\) DO UPDATE/);
  assert.deepEqual(queries[0]!.values,["g1","us-east-1","203.0.113.30:1080"]);
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

test("PgEgressStore.heartbeat updates health and load",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.heartbeat("g1",{loadPercent:33,healthy:true});
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.egress_gateways/);
  assert.deepEqual(queries[0]!.values,["g1",33,true]);
});

test("PgEgressStore.candidates only returns ACTIVE, recently-heartbeated gateways",async()=>{
  const store=new PgEgressStore({
    query:async(text)=>{
      assert.match(text,/state='ACTIVE'/);
      assert.match(text,/last_heartbeat>now\(\)-interval '30 seconds'/);
      return {rows:[{gateway_id:"g1",region:"us-east-1",fixed_ip:"203.0.113.30:1080",is_healthy:true,load_percent:"5.00",last_heartbeat:new Date().toISOString()}]};
    }
  });
  const candidates=await store.candidates();
  assert.equal(candidates.length,1);
  assert.equal(candidates[0]!.id,"g1");
  assert.equal(candidates[0]!.loadPercent,5);
});

test("PgEgressStore.remove deletes the gateway",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEgressStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.remove("g1");
  assert.match(queries[0]!.text,/DELETE FROM bapc_security_core\.egress_gateways/);
});
