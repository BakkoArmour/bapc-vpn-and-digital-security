import test from "node:test";
import assert from "node:assert/strict";
import {PgCommandQueue} from "../../../services/mesh-controller/pg-command-queue.js";

// latestAcknowledgement is NodeReconciliationService's only window into "what
// did this node last report" — command_acknowledgements already had a write
// path (acknowledge, below) but no read path at all before this.

test("PgCommandQueue.latestAcknowledgement returns null when the node has never acknowledged that command type",async()=>{
  const queue=new PgCommandQueue({query:async()=>({rows:[]})});
  assert.equal(await queue.latestAcknowledgement("n1","RECONCILE"),null);
});

test("PgCommandQueue.latestAcknowledgement only considers SUCCEEDED acknowledgements, most recent first",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const queue=new PgCommandQueue({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{command_id:"cmd-2",status:"SUCCEEDED",acknowledged_at:new Date().toISOString(),details:{revision:3,status:"APPLIED"}}]};
    }
  });
  const ack=await queue.latestAcknowledgement("n1","RECONCILE");
  assert.match(queries[0]!.text,/status='SUCCEEDED'/);
  assert.match(queries[0]!.text,/ORDER BY acknowledged_at DESC LIMIT 1/);
  assert.deepEqual(queries[0]!.values,["n1","RECONCILE"]);
  assert.equal(ack!.commandId,"cmd-2");
  assert.equal(ack!.details.revision,3);
});

test("PgCommandQueue.acknowledge marks a failed result FAILED, not SUCCEEDED, so latestAcknowledgement never sees it as in-sync",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const queue=new PgCommandQueue({
    query:async(text,values=[])=>{
      queries.push({text,values});
      if(text.includes("UPDATE"))return {rows:[{node_id:"n1",command_type:"SET_DNS",issued_at:new Date().toISOString()}]};
      return {rows:[]};
    }
  });
  await queue.acknowledge("cmd-1",{ok:false,error:"platform rejected DNS servers"});
  const insert=queries.find(q=>q.text.includes("INSERT INTO bapc_security_core.command_acknowledgements"))!;
  assert.equal(insert.values[4],"FAILED");
});
