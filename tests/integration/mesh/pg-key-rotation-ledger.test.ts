import test from "node:test";
import assert from "node:assert/strict";
import {PgKeyRotationLedger} from "../../../services/mesh-controller/pg-key-rotation-ledger.js";

// KEY_ROTATION_DAYS (config.ts) had no consumer at all — nothing ever read
// a node's rotation history to decide whether it was overdue. This is that
// query's own SQL-shape test; src/application/key-rotation-scheduler.ts
// tests the decision logic built on top of it.

test("PgKeyRotationLedger.nodesOverdueForRotation queries the max rotated_at per node against the configured window",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const now=new Date();
  const ledger=new PgKeyRotationLedger({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{node_id:"n1"},{node_id:"n2"}]};
    }
  });
  const overdue=await ledger.nodesOverdueForRotation(30,now);
  assert.match(queries[0]!.text,/MAX\(rotated_at\)/);
  assert.match(queries[0]!.text,/make_interval\(days=>\$1\)/);
  assert.deepEqual(queries[0]!.values,[30,now]);
  assert.deepEqual(overdue,["n1","n2"]);
});

test("PgKeyRotationLedger.nodesOverdueForRotation returns an empty list when nothing is overdue",async()=>{
  const ledger=new PgKeyRotationLedger({query:async()=>({rows:[]})});
  assert.deepEqual(await ledger.nodesOverdueForRotation(30,new Date()),[]);
});
