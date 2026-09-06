import test from "node:test";
import assert from "node:assert/strict";
import {PgThreatSignalStore} from "../../../services/threat-engine/pg-threat-signal-store.js";

// threat_signal_window (db/017_threat_signal_window.sql) had no repository
// at all before this — ThreatCorrelator's sliding window lived only in a
// process-local Map, erased on every control-plane restart.

test("PgThreatSignalStore.record inserts a real row keyed by nodeId",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgThreatSignalStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  const at=new Date();
  await store.record("n1",{nodeId:"n1",kind:"failed_auth",confidence:1,weight:15,at,metadata:{ip:"10.0.0.1"}});
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.threat_signal_window/);
  assert.deepEqual(queries[0]!.values,["n1","failed_auth",1,15,at,JSON.stringify({ip:"10.0.0.1"})]);
});

test("PgThreatSignalStore.window prunes stale rows before reading, and maps rows back to real ThreatSignals",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const at=new Date();
  const store=new PgThreatSignalStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      if(text.startsWith("DELETE"))return {rows:[]};
      return {rows:[{kind:"scan",confidence:"1.000",weight:"20.00",occurred_at:at.toISOString(),metadata:{}}]};
    }
  });
  const signals=await store.window("n1",at.getTime()-1000);
  assert.match(queries[0]!.text,/DELETE FROM bapc_security_core\.threat_signal_window WHERE node_key=\$1 AND occurred_at<\$2/);
  assert.match(queries[1]!.text,/SELECT[\s\S]*FROM bapc_security_core\.threat_signal_window WHERE node_key=\$1 ORDER BY occurred_at/);
  assert.equal(signals.length,1);
  assert.equal(signals[0]!.nodeId,"n1");
  assert.equal(signals[0]!.confidence,1);
  assert.equal(signals[0]!.weight,20);
});

// The __unattributed__ sentinel (ThreatCorrelator.ingest's own convention for
// a signal with no nodeId) must round-trip back to a signal with NO nodeId
// field at all, not the literal string "__unattributed__" as a fake node.
test("PgThreatSignalStore.window omits nodeId for the __unattributed__ sentinel key",async()=>{
  const store=new PgThreatSignalStore({
    query:async(text)=>text.startsWith("DELETE")?{rows:[]}:{rows:[{kind:"scan",confidence:"0.500",weight:"10.00",occurred_at:new Date().toISOString(),metadata:{}}]}
  });
  const [signal]=await store.window("__unattributed__",0);
  assert.equal("nodeId" in signal!,false);
});

test("PgThreatSignalStore.clear deletes every row for the node and returns the count",async()=>{
  const store=new PgThreatSignalStore({query:async()=>({rows:[{signal_id:"s1"},{signal_id:"s2"}]})});
  assert.equal(await store.clear("n1"),2);
});

test("PgThreatSignalStore.activeWindows groups by node, most recently active first",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgThreatSignalStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{node_key:"n2",signal_count:3,latest_at:new Date().toISOString()}]};
    }
  });
  const active=await store.activeWindows(Date.now()-300_000);
  assert.match(queries[0]!.text,/GROUP BY node_key ORDER BY latest_at DESC/);
  assert.equal(active[0]!.nodeKey,"n2");
  assert.equal(active[0]!.signalCount,3);
});

// Full end-to-end restart-survival proof against a REAL Postgres. Skipped
// unless DATABASE_URL points at a reachable database, e.g.:
//   docker compose -f deploy/docker-compose.yml up -d postgres
//   DATABASE_URL=postgres://bapc_security:...@localhost:5432/bapc_security_core npm test
const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: a signal recorded before a simulated restart still contributes to correlation after it",{skip:!liveDatabaseUrl},async()=>{
  const {Postgres}=await import("../../../src/infrastructure/postgres/client.js");
  const {ThreatEngine}=await import("../../../services/threat-engine/engine.js");
  const {ThreatCorrelator}=await import("../../../services/threat-engine/correlator.js");
  const db=new Postgres(liveDatabaseUrl!);
  const nodeId=`live-test-${Date.now()}`;
  try{
    const buildCorrelator=(actions:string[])=>new ThreatCorrelator(
      new ThreatEngine({
        reauthenticate:async()=>{},terminateJit:async()=>{actions.push("jit");},
        isolate:async()=>{actions.push("isolate");},revokeNodeCertificates:async()=>{},
        rotateMeshIdentity:async()=>{},restore:async()=>{}
      },{open:async()=>{},event:async()=>{}}),
      300_000,undefined,new PgThreatSignalStore(db)
    );
    await buildCorrelator([]).ingest({nodeId,kind:"failed_auth",confidence:1,weight:60,at:new Date(),metadata:{}});
    // A brand-new PgThreatSignalStore/ThreatCorrelator pair — nothing shared
    // in process memory — simulating the control plane having restarted.
    const actionsAfterRestart:string[]=[];
    const result=await buildCorrelator(actionsAfterRestart).ingest({
      nodeId,kind:"failed_auth",confidence:1,weight:20,at:new Date(),metadata:{}
    });
    assert.equal(result.score,80);
    assert.equal(result.severity,"CRITICAL");
    assert.ok(actionsAfterRestart.includes("isolate"));
  }finally{
    await new PgThreatSignalStore(db).clear(nodeId);
    await db.close();
  }
});
