import test from "node:test";
import assert from "node:assert/strict";
import {PgRolloutStore} from "../../../src/infrastructure/pg-rollout-store.js";

// policy_rollout_nodes (db/018_policy_rollout_nodes.sql) had no repository
// at all before this — SafeApplyService's success criterion was ONLY the
// control plane's own database health, never anything a targeted node
// actually reported.

test("PgRolloutStore.start inserts a PENDING row per targeted node, tolerating a re-run",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRolloutStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.start("commit-1",["n1","n2"]);
  assert.equal(queries.length,2);
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.policy_rollout_nodes/);
  assert.match(queries[0]!.text,/ON CONFLICT\(commit_id,node_id\) DO NOTHING/);
  assert.deepEqual(queries[0]!.values,["commit-1","n1"]);
  assert.deepEqual(queries[1]!.values,["commit-1","n2"]);
});

// SUCCEEDED passes through; anything else (FAILED, or the ambiguous
// ACKNOWLEDGED a result with no boolean `ok` produces) is treated as FAILED
// — a rollout's safety decision should never treat "not sure" as success.
test("PgRolloutStore.refresh advances PENDING rows to SUCCEEDED or FAILED from real command_acknowledgements",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRolloutStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      if(text.includes("SELECT node_id,status,acknowledged_at,details FROM bapc_security_core.command_acknowledgements")){
        return {rows:[
          {node_id:"n1",status:"SUCCEEDED",acknowledged_at:new Date().toISOString(),details:{commitId:"commit-1",ok:true}},
          {node_id:"n2",status:"ACKNOWLEDGED",acknowledged_at:new Date().toISOString(),details:{commitId:"commit-1"}}
        ]};
      }
      if(text.includes("SELECT node_id,status,acknowledged_at,details FROM bapc_security_core.policy_rollout_nodes")){
        return {rows:[{node_id:"n1",status:"SUCCEEDED",acknowledged_at:new Date().toISOString(),details:{}},{node_id:"n2",status:"FAILED",acknowledged_at:new Date().toISOString(),details:{}}]};
      }
      return {rows:[]};
    }
  });
  const summary=await store.refresh("commit-1");
  const updateQueries=queries.filter(q=>q.text.includes("UPDATE bapc_security_core.policy_rollout_nodes"));
  assert.equal(updateQueries.length,2);
  assert.equal(updateQueries[0]!.values[2],"SUCCEEDED");
  assert.equal(updateQueries[1]!.values[2],"FAILED");
  assert.equal(summary.find(s=>s.nodeId==="n1")!.status,"SUCCEEDED");
  assert.equal(summary.find(s=>s.nodeId==="n2")!.status,"FAILED");
});

test("PgRolloutStore.refresh only updates rows still PENDING, never overwriting an already-finalized row",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRolloutStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[]};
    }
  });
  await store.refresh("commit-1");
  // With no acks returned, no UPDATE should be attempted at all.
  assert.equal(queries.some(q=>q.text.includes("UPDATE")),false);
});

test("PgRolloutStore.finalizeTimeouts marks every still-PENDING row TIMED_OUT",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRolloutStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.finalizeTimeouts("commit-1");
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.policy_rollout_nodes SET status='TIMED_OUT' WHERE commit_id=\$1 AND status='PENDING'/);
  assert.deepEqual(queries[0]!.values,["commit-1"]);
});

test("PgRolloutStore.markRolledBack sets every row for the commit to ROLLED_BACK, regardless of prior status",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRolloutStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  await store.markRolledBack("commit-1");
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.policy_rollout_nodes SET status='ROLLED_BACK' WHERE commit_id=\$1$/);
  assert.doesNotMatch(queries[0]!.text,/AND status/);
});

test("PgRolloutStore.summary maps rows back to real NodeRolloutRecords",async()=>{
  const at=new Date();
  const store=new PgRolloutStore({
    query:async()=>({rows:[{node_id:"n1",status:"SUCCEEDED",acknowledged_at:at.toISOString(),details:JSON.stringify({ok:true})}]})
  });
  const [record]=await store.summary("commit-1");
  assert.equal(record!.nodeId,"n1");
  assert.equal(record!.status,"SUCCEEDED");
  assert.deepEqual(record!.details,{ok:true});
  assert.equal(record!.acknowledgedAt!.getTime(),at.getTime());
});

test("PgRolloutStore.summary omits acknowledgedAt for a still-PENDING row",async()=>{
  const store=new PgRolloutStore({
    query:async()=>({rows:[{node_id:"n1",status:"PENDING",acknowledged_at:null,details:{}}]})
  });
  const [record]=await store.summary("commit-1");
  assert.equal("acknowledgedAt" in record!,false);
});
