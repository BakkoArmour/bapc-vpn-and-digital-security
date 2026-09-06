import test from "node:test";
import assert from "node:assert/strict";
import {ThreatEngine} from "../../../services/threat-engine/engine.js";
import {ThreatCorrelator} from "../../../services/threat-engine/correlator.js";
import {PgThreatActionPort} from "../../../services/threat-engine/pg-threat-action-port.js";
import {PgIncidentPort} from "../../../services/threat-engine/pg-incident-port.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus, InMemoryEnforcer} from "../../../src/infrastructure/adapters.js";
import type {MeshNode} from "../../../src/domain/types.js";

// The exact gap this closes: ThreatResponseService scores one SecurityEvent
// at a time with no memory across calls, so five weak posture failures from
// the same node — each individually unremarkable — never became anything.
// This wires the real pieces together the way production-server.ts does
// and proves five weak posture-failure signals actually reach a real
// isolate() call, not just an isolated ThreatCorrelator/ThreatEngine unit
// test against a fake action port.

class FakeQueue {
  enqueued:Array<{nodeId:string;type:string}>=[];
  async enqueue(nodeId:string,type:string){this.enqueued.push({nodeId,type});}
  async hasPending(){return false;}
}
class FakeCertificateStore {
  revoked:string[]=[];
  async activeCertificateFor(){return {serial:"cert-1"};}
  async revoke(serial:string){this.revoked.push(serial);}
}
class FakeDb {async query(){return {rows:[]};}}

const node=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});

test("five weak posture-failure signals from the same node reach a real isolate() call",async()=>{
  const store=new MemoryStore();
  await store.save(node("n1"));
  const enforcer=new InMemoryEnforcer();
  const queue=new FakeQueue();
  const actionPort=new PgThreatActionPort(store,store,enforcer as any,new FakeCertificateStore() as any,queue as any,new MemoryBus());
  const incidentPort=new PgIncidentPort(new FakeDb(),store,new RandomIds(),new SystemClock());
  const engine=new ThreatEngine(actionPort,incidentPort);
  const correlator=new ThreatCorrelator(engine);

  let result;
  for(let i=0;i<5;i++){
    result=await correlator.ingest({nodeId:"n1",kind:"posture_failure",confidence:1,weight:15,at:new Date(),metadata:{}});
  }

  assert.equal(result!.severity,"CRITICAL");
  assert.ok(enforcer.isolated.has("n1"),"the node should actually be isolated, not just scored");
  // One THREAT_EVALUATED event per ingest() call (5), each logging that
  // call's own severity — the escalation only reaches CRITICAL on the 5th.
  assert.equal(store.events.length,5);
  assert.ok(store.events.every(e=>e.type==="THREAT_EVALUATED"));
  assert.equal(store.events.at(-1)!.severity,"CRITICAL");
});

test("a single posture failure alone stays INFO and never isolates anything",async()=>{
  const store=new MemoryStore();
  await store.save(node("n1"));
  const enforcer=new InMemoryEnforcer();
  const actionPort=new PgThreatActionPort(store,store,enforcer as any,new FakeCertificateStore() as any,new FakeQueue() as any,new MemoryBus());
  const incidentPort=new PgIncidentPort(new FakeDb(),store,new RandomIds(),new SystemClock());
  const correlator=new ThreatCorrelator(new ThreatEngine(actionPort,incidentPort));

  const result=await correlator.ingest({nodeId:"n1",kind:"posture_failure",confidence:1,weight:15,at:new Date(),metadata:{}});
  assert.equal(result.severity,"INFO");
  assert.equal(enforcer.isolated.size,0);
});

test("an EMERGENCY-tier evaluation revokes the certificate and requests an identity rotation, never rotating server-side",async()=>{
  const store=new MemoryStore();
  await store.save(node("n1"));
  const enforcer=new InMemoryEnforcer();
  const queue=new FakeQueue();
  const certs=new FakeCertificateStore();
  const actionPort=new PgThreatActionPort(store,store,enforcer as any,certs as any,queue as any,new MemoryBus());
  const incidentPort=new PgIncidentPort(new FakeDb(),store,new RandomIds(),new SystemClock());
  const correlator=new ThreatCorrelator(new ThreatEngine(actionPort,incidentPort));

  const result=await correlator.ingest({nodeId:"n1",kind:"critical_exploit_signature",confidence:1,weight:90,at:new Date(),metadata:{}});

  assert.equal(result.severity,"EMERGENCY");
  assert.deepEqual(certs.revoked,["cert-1"]);
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.type,"ROTATE_IDENTITY_REQUIRED");
  // Never a raw wireguard-public-key value or any key material queued —
  // this command carries no key at all, since the node generates its own.
});
