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
const testNode=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});
const policy:NetworkPolicy={
  id:"p1",name:"deny-legacy-port",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
  protocols:["TCP"],destinationPorts:[8080],action:"DENY",requiredRoles:[],requiresJit:false,
  priority:10,version:1,active:true
};

test("SafeApplyService.apply delivers a real APPLY_FIREWALL command to every active node, then commits when the probe is healthy",async()=>{
  const queue=new FakeQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodes([testNode("n1"),testNode("n2")]) as any);
  const service=new SafeApplyService(enforcer,{verifyControlPlane:async()=>true},new MemoryBus(),new RandomIds(),new SystemClock());
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"COMMITTED");
  assert.equal(queue.enqueued.length,2);
  assert.ok(queue.enqueued.every(e=>e.type==="APPLY_FIREWALL"));
  // Committing doesn't also send a rollback.
  assert.equal(queue.enqueued.some(e=>e.type==="ROLLBACK_FIREWALL"),false);
});

test("SafeApplyService.apply rolls back a bad policy on every active node when the control plane probe fails",async()=>{
  const queue=new FakeQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodes([testNode("n1")]) as any);
  const service=new SafeApplyService(enforcer,{verifyControlPlane:async()=>false},new MemoryBus(),new RandomIds(),new SystemClock());
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"ROLLED_BACK");
  assert.deepEqual(queue.enqueued.map(e=>e.type),["APPLY_FIREWALL","ROLLBACK_FIREWALL"]);
});
