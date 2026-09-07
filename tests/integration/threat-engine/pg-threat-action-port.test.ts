import test from "node:test";
import assert from "node:assert/strict";
import {PgThreatActionPort} from "../../../services/threat-engine/pg-threat-action-port.js";
import {MemoryStore, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus, InMemoryEnforcer} from "../../../src/infrastructure/adapters.js";
import type {MeshNode} from "../../../src/domain/types.js";

// ThreatEngine existed fully built and tested with no real ThreatActionPort
// anywhere. This is that port. rotateMeshIdentity is the one method that
// can't just delegate to something that already existed — see its own
// comment for why it enqueues a command instead of rotating anything
// server-side.

class FakeQueue {
  enqueued:Array<{nodeId:string;type:string;payload:unknown}>=[];
  async enqueue(nodeId:string,type:string,payload:unknown){this.enqueued.push({nodeId,type,payload});}
  async hasPending(nodeId:string,type:string){return this.enqueued.some(e=>e.nodeId===nodeId&&e.type===type);}
}
class FakeCertificateStore {
  revoked:Array<{serial:string;reason:string}>=[];
  private active:{serial:string}|undefined;
  constructor(active?:{serial:string}){this.active=active;}
  async activeCertificateFor(){return this.active;}
  async revoke(serial:string,reason:string){this.revoked.push({serial,reason});}
}

const node=(id:string,zone:MeshNode["zone"]="ZONE_PROD_APP"):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone,active:true
});

test("reauthenticate publishes a challenge-required event",async()=>{
  const bus=new MemoryBus();
  const port=new PgThreatActionPort(new MemoryStore() as any,new MemoryStore() as any,new InMemoryEnforcer() as any,new FakeCertificateStore() as any,new FakeQueue() as any,bus);
  await port.reauthenticate("node-1");
  assert.equal(bus.events.length,1);
  assert.equal(bus.events[0]!.topic,"security.challenge.required");
});

test("terminateJit terminates only active grants in the node's zone",async()=>{
  const store=new MemoryStore();
  await store.save(node("n1","ZONE_PROD_APP"));
  const now=new Date();
  await store.save({id:"g1",userId:"u1",targetResource:"api",targetZone:"ZONE_PROD_APP",justification:"x".repeat(20),grantedAt:now,expiresAt:new Date(now.getTime()+60_000),terminated:false});
  await store.save({id:"g2",userId:"u2",targetResource:"api",targetZone:"ZONE_DEV",justification:"x".repeat(20),grantedAt:now,expiresAt:new Date(now.getTime()+60_000),terminated:false});
  const port=new PgThreatActionPort(store,store,new InMemoryEnforcer() as any,new FakeCertificateStore() as any,new FakeQueue() as any,new MemoryBus());
  await port.terminateJit("n1");
  const g1=await store.get("g1") as any, g2=await store.get("g2") as any;
  assert.equal(g1.terminated,true);
  assert.equal(g2.terminated,false);
});

test("isolate/restore delegate to the real PolicyEnforcer",async()=>{
  const enforcer=new InMemoryEnforcer();
  const port=new PgThreatActionPort(new MemoryStore() as any,new MemoryStore() as any,enforcer as any,new FakeCertificateStore() as any,new FakeQueue() as any,new MemoryBus());
  await port.isolate("n1","test");
  assert.ok(enforcer.isolated.has("n1"));
  await port.restore("n1");
  assert.ok(!enforcer.isolated.has("n1"));
});

test("revokeNodeCertificates revokes the node's active certificate",async()=>{
  const certs=new FakeCertificateStore({serial:"abc123"});
  const port=new PgThreatActionPort(new MemoryStore() as any,new MemoryStore() as any,new InMemoryEnforcer() as any,certs as any,new FakeQueue() as any,new MemoryBus());
  await port.revokeNodeCertificates("n1","emergency containment");
  assert.deepEqual(certs.revoked,[{serial:"abc123",reason:"emergency containment"}]);
});

test("revokeNodeCertificates does nothing gracefully when the node has no active certificate",async()=>{
  const certs=new FakeCertificateStore(undefined);
  const port=new PgThreatActionPort(new MemoryStore() as any,new MemoryStore() as any,new InMemoryEnforcer() as any,certs as any,new FakeQueue() as any,new MemoryBus());
  await port.revokeNodeCertificates("n1","emergency containment");
  assert.equal(certs.revoked.length,0);
});

test("rotateMeshIdentity enqueues ROTATE_IDENTITY_REQUIRED — never rotates anything itself",async()=>{
  const queue=new FakeQueue();
  const store=new MemoryStore();
  await store.save(node("n1"));
  const port=new PgThreatActionPort(store,new MemoryStore() as any,new InMemoryEnforcer() as any,new FakeCertificateStore() as any,queue as any,new MemoryBus());
  await port.rotateMeshIdentity("n1");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"n1");
  assert.equal(queue.enqueued[0]!.type,"ROTATE_IDENTITY_REQUIRED");
});

// A node stuck in EMERGENCY (chronic posture failures) re-triggers this on
// every heartbeat until dismissed — without a dedup check this would pile
// up a fresh ROTATE_IDENTITY_REQUIRED row per heartbeat, forever.
test("rotateMeshIdentity does not enqueue a second ROTATE_IDENTITY_REQUIRED while one is already pending",async()=>{
  const queue=new FakeQueue();
  const store=new MemoryStore();
  await store.save(node("n1"));
  const port=new PgThreatActionPort(store,new MemoryStore() as any,new InMemoryEnforcer() as any,new FakeCertificateStore() as any,queue as any,new MemoryBus());
  await port.rotateMeshIdentity("n1");
  await port.rotateMeshIdentity("n1");
  await port.rotateMeshIdentity("n1");
  assert.equal(queue.enqueued.length,1);
});

// controller_commands.node_id is a real foreign key into mesh_nodes —
// ThreatEngine.evaluate calls this for any nodeId a threat signal names,
// and not every caller of POST /api/v1/threats/signal is guaranteed to name
// a currently-enrolled node. Found live against real Postgres: a stale
// nodeId crashed the whole request with a foreign-key violation instead of
// just skipping a rotation nothing could ever act on.
test("rotateMeshIdentity does nothing for a node that isn't actually enrolled",async()=>{
  const queue=new FakeQueue();
  const port=new PgThreatActionPort(new MemoryStore() as any,new MemoryStore() as any,new InMemoryEnforcer() as any,new FakeCertificateStore() as any,queue as any,new MemoryBus());
  await port.rotateMeshIdentity("does-not-exist");
  assert.equal(queue.enqueued.length,0);
});
