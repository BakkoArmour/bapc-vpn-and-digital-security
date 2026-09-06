import test from "node:test";
import assert from "node:assert/strict";
import {SafeApplyService} from "../../../src/application/safe-apply.js";
import {PgPolicyEnforcer} from "../../../src/infrastructure/pg-policy-enforcer.js";
import {RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus} from "../../../src/infrastructure/adapters.js";
import type {NetworkPolicy, MeshNode} from "../../../src/domain/types.js";

// SafeApplyService existed with no caller anywhere in production and
// InMemoryEnforcer's stage/rollback only touched a Map — so there was
// nothing end-to-end proving a staged policy actually reaches a node, or
// that a bad apply actually gets rolled back on the node, not just in
// memory. This exercises the real PgPolicyEnforcer against a fake queue and
// node repository (no live Postgres needed for the fake) the same way
// production-server.ts wires it.
class FakeQueue {
  enqueued:Array<{nodeId:string;type:string;payload:unknown}>=[];
  async enqueue(nodeId:string,type:string,payload:unknown){this.enqueued.push({nodeId,type,payload});}
}
class FakeNodes {
  constructor(private nodes:MeshNode[]){}
  async list(){return this.nodes;}
  async get(){return undefined;}
  async findByPublicKey(){return undefined;}
  async save(){}
}
class FakeDb {
  queries:Array<{text:string;values:unknown[]}>=[];
  async query(text:string,values:unknown[]=[]){this.queries.push({text,values});return {rows:[]};}
}
// The real PgRolloutStore is exercised on its own (pg-rollout-store.test.ts)
// — this fake just reports every targeted node SUCCEEDED as soon as it's
// asked, so these tests can focus on proving PgPolicyEnforcer's own wiring
// (APPLY_FIREWALL delivery, policy_commits persistence) without waiting out
// SafeApplyService's real polling/timeout window for a fake command queue
// that never produces a real command_acknowledgements row on its own.
class FakeRolloutStore {
  private targets:string[]=[];
  async start(_commitId:string,nodeIds:string[]){this.targets=nodeIds;}
  async refresh(){return this.summary();}
  async finalizeTimeouts(){}
  async markRolledBack(){}
  async summary(){return this.targets.map(nodeId=>({nodeId,status:"SUCCEEDED" as const,details:{}}));}
}
const testNode=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});
const policy:NetworkPolicy={
  id:"p1",name:"deny-legacy-port",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
  protocols:["TCP"],destinationPorts:[8080],action:"DENY",requiredRoles:[],requiresJit:false,
  priority:10,version:1,active:true
};

test("SafeApplyService.apply delivers a real APPLY_FIREWALL command to every active node, persists the commit, then commits when the probe is healthy",async()=>{
  const queue=new FakeQueue();
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodes([testNode("n1"),testNode("n2")]) as any,db as any);
  const service=new SafeApplyService(enforcer,{verifyControlPlane:async()=>true},new MemoryBus(),new RandomIds(),new SystemClock(),new FakeRolloutStore() as any);
  const result=await service.apply([policy],5_000,"user-1");
  assert.equal(result.status,"COMMITTED");
  assert.equal(queue.enqueued.length,2);
  assert.ok(queue.enqueued.every(e=>e.type==="APPLY_FIREWALL"));
  // Committing doesn't also send a rollback.
  assert.equal(queue.enqueued.some(e=>e.type==="ROLLBACK_FIREWALL"),false);
  // policy_commits existed with no write path at all — SafeApplyService's
  // whole stage/commit/rollback lifecycle previously lived only in an
  // in-memory Map whose stored value was never even read back.
  assert.match(db.queries[0]!.text,/INSERT INTO bapc_security_core\.policy_commits/);
  assert.equal(db.queries[0]!.values[2],"user-1");
  assert.match(db.queries.at(-1)!.text,/UPDATE bapc_security_core\.policy_commits SET status='COMMITTED'/);
});

test("SafeApplyService.apply rolls back a bad policy on every active node when the control plane probe fails",async()=>{
  const queue=new FakeQueue();
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodes([testNode("n1")]) as any,db as any);
  const service=new SafeApplyService(enforcer,{verifyControlPlane:async()=>false},new MemoryBus(),new RandomIds(),new SystemClock());
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"ROLLED_BACK");
  assert.deepEqual(queue.enqueued.map(e=>e.type),["APPLY_FIREWALL","ROLLBACK_FIREWALL"]);
  assert.match(db.queries.at(-1)!.text,/UPDATE bapc_security_core\.policy_commits SET status='ROLLED_BACK'/);
});
