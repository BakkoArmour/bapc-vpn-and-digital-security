import test from "node:test";
import assert from "node:assert/strict";
import {PgRelayStore} from "../../../services/relay-fleet/pg-relay-store.js";

test("PgRelayStore issues the expected SQL for insert, get and remove",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRelayStore({
    query:async(text:string,values:unknown[]=[])=>{
      queries.push({text,values});
      if(text.includes("SELECT"))return {rows:[{relay_id:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",is_available:true,instance_id:"i-abc"}]};
      return {rows:[]};
    }
  });
  await store.insert("r1","us-east-1","203.0.113.10:51900","i-abc");
  const row=await store.get("r1");
  await store.remove("r1");

  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.relays/);
  assert.deepEqual(queries[0]!.values,["r1","us-east-1","203.0.113.10:51900","i-abc",null]);
  assert.match(queries[1]!.text,/SELECT .* FROM bapc_security_core\.relays/);
  assert.deepEqual(row,{relayId:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",isAvailable:true,instanceId:"i-abc"});
  assert.match(queries[2]!.text,/DELETE FROM bapc_security_core\.relays/);
});

test("PgRelayStore.get returns null for an unknown relay",async()=>{
  const store=new PgRelayStore({query:async()=>({rows:[]})});
  assert.equal(await store.get("missing"),null);
});

// Self-registration (src/runtime/relay-server.ts) has no AWS instance id —
// previously insert() required one and had no ON CONFLICT, so a restarting
// relay re-registering with the same id would error instead of upserting.
// It reports its own configured capacity (RELAY_MAX_SESSIONS/20) instead
// of leaving capacity_mbps at the schema's generic default forever.
test("PgRelayStore.insert upserts, accepts no instanceId, and reports real capacity for self-registered relays",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRelayStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.insert("r2","us-west-2","203.0.113.20:51900",undefined,25);
  assert.match(queries[0]!.text,/ON CONFLICT\(relay_id\) DO UPDATE/);
  assert.deepEqual(queries[0]!.values,["r2","us-west-2","203.0.113.20:51900",null,25]);
});

// load_percent/latency_ms/last_heartbeat/active_sessions/
// throughput_bytes_per_sec had no write path at all before this — a
// relay's recorded health was frozen at whatever insert() set it to
// (0/0/0/0), forever. Real values now come from src/runtime/relay-
// server.ts's actual measurements (see native/shared/process-metrics.ts).
test("PgRelayStore.heartbeat updates health, sessions and throughput and marks the relay available",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRelayStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.heartbeat("r1",{loadPercent:42,latencyMs:80,activeSessions:12,throughputBytesPerSec:5000});
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.relays/);
  assert.deepEqual(queries[0]!.values,["r1",42,80,12,5000]);
});

const relayRow=(overrides:Record<string,unknown>={})=>({
  relay_id:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",load_percent:"10.00",latency_ms:30,
  is_available:true,last_heartbeat:new Date().toISOString(),
  active_sessions:100,capacity_mbps:10,throughput_bytes_per_sec:"2000",...overrides
});

// Unlike candidates(), list() must show stale/unavailable relays too — an
// operator diagnosing an outage needs to see what dropped out.
test("PgRelayStore.list returns every relay, including a stale one candidates() would exclude",async()=>{
  const store=new PgRelayStore({
    query:async(text)=>{
      assert.doesNotMatch(text,/WHERE/);
      return {rows:[
        relayRow(),
        relayRow({relay_id:"r2",region:"us-west-2",endpoint:"203.0.113.20:51900",load_percent:"0.00",latency_ms:0,is_available:false,last_heartbeat:null,active_sessions:0,capacity_mbps:1000,throughput_bytes_per_sec:"0"})
      ]};
    }
  });
  const all=await store.list();
  assert.equal(all.length,2);
  assert.equal(all[1]!.available,false);
});

test("PgRelayStore.candidates only returns relays heartbeated within the freshness window",async()=>{
  const store=new PgRelayStore({
    query:async(text)=>{
      assert.match(text,/last_heartbeat>now\(\)-interval '45 seconds'/);
      return {rows:[relayRow()]};
    }
  });
  const candidates=await store.candidates();
  assert.equal(candidates.length,1);
  assert.equal(candidates[0]!.id,"r1");
  assert.equal(candidates[0]!.loadPercent,10);
  assert.equal(candidates[0]!.latencyMs,30);
  assert.equal(candidates[0]!.activeSessions,100);
  assert.equal(candidates[0]!.throughputBytesPerSec,2000);
});

// capacityPercent is computed from active_sessions/(capacity_mbps*20), the
// convention the now-deleted RelayRegistry used — 100 sessions against a
// 10 Mbps (=200 session) ceiling is 50%.
test("PgRelayStore computes capacityPercent from active_sessions/capacity_mbps at read time",async()=>{
  const store=new PgRelayStore({query:async()=>({rows:[relayRow({active_sessions:100,capacity_mbps:10})]})});
  const [candidate]=await store.candidates();
  assert.equal(candidate!.capacityPercent,50);
});

test("PgRelayStore.candidates reports 0% capacity, not NaN, when capacity_mbps is 0",async()=>{
  const store=new PgRelayStore({query:async()=>({rows:[relayRow({capacity_mbps:0})]})});
  const [candidate]=await store.candidates();
  assert.equal(candidate!.capacityPercent,0);
});
