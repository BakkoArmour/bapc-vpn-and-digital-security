import test from "node:test";
import assert from "node:assert/strict";
import {PgPolicyEnforcer} from "../../../src/infrastructure/pg-policy-enforcer.js";
import {MemoryStore} from "../../../src/infrastructure/memory.js";

// controller_commands.node_id is a real foreign key into mesh_nodes —
// isolateNode/restoreNode previously enqueued a command for ANY nodeId
// unconditionally. ThreatEngine.evaluate calls isolate() for nodeIds it
// never validated (some threat signals come from callers other than its own
// trusted heartbeat path — see /api/v1/threats/signal), so a stale/mistyped
// nodeId crashed the whole request with a foreign-key violation, found live
// against real Postgres, not by any test that mocks db.query.

class FakeQueue {
  enqueued:Array<{nodeId:string;type:string}>=[];
  async enqueue(nodeId:string,type:string){this.enqueued.push({nodeId,type});}
  async hasPending(){return false;}
}

test("isolateNode does nothing for a node that isn't actually enrolled",async()=>{
  const queue=new FakeQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new MemoryStore(),{query:async()=>({rows:[]})});
  await enforcer.isolateNode("does-not-exist");
  assert.equal(queue.enqueued.length,0);
});

test("isolateNode enqueues QUARANTINE for a real, enrolled node",async()=>{
  const queue=new FakeQueue();
  const store=new MemoryStore();
  await store.save({id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",listenPort:1,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});
  const enforcer=new PgPolicyEnforcer(queue as any,store,{query:async()=>({rows:[]})});
  await enforcer.isolateNode("n1");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.type,"QUARANTINE");
});

test("restoreNode does nothing for a node that isn't actually enrolled",async()=>{
  const queue=new FakeQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new MemoryStore(),{query:async()=>({rows:[]})});
  await enforcer.restoreNode("does-not-exist");
  assert.equal(queue.enqueued.length,0);
});

test("restoreNode enqueues RESTORE for a real, enrolled node",async()=>{
  const queue=new FakeQueue();
  const store=new MemoryStore();
  await store.save({id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",listenPort:1,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});
  const enforcer=new PgPolicyEnforcer(queue as any,store,{query:async()=>({rows:[]})});
  await enforcer.restoreNode("n1");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.type,"RESTORE");
});
