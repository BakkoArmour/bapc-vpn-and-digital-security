import test from "node:test";
import assert from "node:assert/strict";
import {PgPolicyEnforcer} from "../../../src/infrastructure/pg-policy-enforcer.js";
import {PgMeshCommandSink} from "../../../services/mesh-controller/pg-mesh-command-sink.js";
import type {MeshNode, NetworkPolicy} from "../../../src/domain/types.js";

const testNode=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});
class FakeNodeRepository {
  constructor(private nodes:MeshNode[]){}
  async list(){return this.nodes;}
  async get(id:string){return this.nodes.find(n=>n.id===id);}
  async findByPublicKey(){return undefined;}
  async save(){}
}

// PgPolicyEnforcer and PgMeshCommandSink both persist to controller_commands
// via PgCommandQueue, which is drained by two independent consumers with two
// different command-type vocabularies: ProductionAgent.execute (REST
// endpoint agent — "QUARANTINE", "RESTORE", ...) and mesh.proto's
// ControllerCommand.Action (gRPC — "QUARANTINE_NODE", "RELOAD_POLICIES", ...
// translated in src/api/grpc/server.ts's controllerActionFor). These tests
// pin down that the command types actually enqueued are the ones
// ProductionAgent.execute implements, since that's the only real consumer
// today — using the mesh.proto names instead would enqueue a command the
// agent can't execute (see git history: that was the bug this fixes).
class FakeCommandQueue {
  enqueued:Array<{nodeId:string;type:string;payload:unknown;priority:number}>=[];
  async enqueue(nodeId:string,type:string,payload:unknown,priority=100){
    this.enqueued.push({nodeId,type,payload,priority});
  }
}
class FakeDb {
  queries:Array<{text:string;values:unknown[]}>=[];
  async query(text:string,values:unknown[]=[]){this.queries.push({text,values});return {rows:[]};}
}

test("PgPolicyEnforcer.isolateNode enqueues QUARANTINE, the type ProductionAgent.execute implements",async()=>{
  const queue=new FakeCommandQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodeRepository([testNode("node-1")]) as any,new FakeDb() as any);
  await enforcer.isolateNode("node-1");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"node-1");
  assert.equal(queue.enqueued[0]!.type,"QUARANTINE");
});

test("PgPolicyEnforcer.restoreNode enqueues RESTORE, the type ProductionAgent.execute implements",async()=>{
  const queue=new FakeCommandQueue();
  const enforcer=new PgPolicyEnforcer(queue as any,new FakeNodeRepository([testNode("node-1")]) as any,new FakeDb() as any);
  await enforcer.restoreNode("node-1");
  assert.equal(queue.enqueued[0]!.type,"RESTORE");
});

test("PgPolicyEnforcer.stage broadcasts a real APPLY_FIREWALL command to every active node and persists it to policy_commits",async()=>{
  const queue=new FakeCommandQueue();
  const nodes=new FakeNodeRepository([testNode("n1"),testNode("n2")]);
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(queue as any,nodes as any,db as any);
  const policy:NetworkPolicy={
    id:"p1",name:"deny-all-dev",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[443],action:"DENY",requiredRoles:[],requiresJit:false,
    priority:10,version:1,active:true
  };
  await enforcer.stage("commit-1",[policy],"user-1");
  assert.match(db.queries[0]!.text,/INSERT INTO bapc_security_core\.policy_commits/);
  assert.deepEqual(db.queries[0]!.values,["commit-1",JSON.stringify([policy]),"user-1"]);
  assert.equal(queue.enqueued.length,2);
  assert.deepEqual(queue.enqueued.map(e=>e.nodeId).sort(),["n1","n2"]);
  for(const entry of queue.enqueued){
    assert.equal(entry.type,"APPLY_FIREWALL");
    const payload=entry.payload as {commitId:string;defaultAction:string;rules:Array<{id:string;action:string;ports:number[]}>};
    assert.equal(payload.commitId,"commit-1");
    assert.equal(payload.rules[0]!.id,"p1");
    assert.equal(payload.rules[0]!.action,"DENY");
    assert.deepEqual(payload.rules[0]!.ports,[443]);
  }
});

// PolicyCompiler existed fully built and tested with no caller anywhere —
// an invalid policy would previously be broadcast to every node as-is,
// only to fail unpredictably inside whatever native nft/WFP call actually
// tried to apply it. This proves stage() now rejects it before anything is
// ever sent.
test("PgPolicyEnforcer.stage rejects an invalid policy before broadcasting anything or persisting it",async()=>{
  const queue=new FakeCommandQueue();
  const nodes=new FakeNodeRepository([testNode("n1")]);
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(queue as any,nodes as any,db as any);
  const invalidPortPolicy:NetworkPolicy={
    id:"p1",name:"bad-port",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[99999],action:"DENY",requiredRoles:[],requiresJit:false,
    priority:10,version:1,active:true
  };
  await assert.rejects(()=>enforcer.stage("commit-1",[invalidPortPolicy]),/invalid port/);
  assert.equal(queue.enqueued.length,0);
  assert.equal(db.queries.length,0);
});

test("PgPolicyEnforcer.stage defaults initiatedBy to a well-known system id when the caller doesn't track one",async()=>{
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(new FakeCommandQueue() as any,new FakeNodeRepository([]) as any,db as any);
  const policy:NetworkPolicy={
    id:"p1",name:"deny-all-dev",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[443],action:"DENY",requiredRoles:[],requiresJit:false,
    priority:10,version:1,active:true
  };
  await enforcer.stage("commit-1",[policy]);
  assert.equal(db.queries[0]!.values[2],"00000000-0000-0000-0000-000000000000");
});

test("PgPolicyEnforcer.rollback broadcasts ROLLBACK_FIREWALL to every active node and marks the commit rolled back",async()=>{
  const queue=new FakeCommandQueue();
  const nodes=new FakeNodeRepository([testNode("n1")]);
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(queue as any,nodes as any,db as any);
  await enforcer.rollback("commit-1");
  assert.match(db.queries[0]!.text,/UPDATE bapc_security_core\.policy_commits SET status='ROLLED_BACK'/);
  assert.deepEqual(db.queries[0]!.values,["commit-1"]);
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"n1");
  assert.equal(queue.enqueued[0]!.type,"ROLLBACK_FIREWALL");
  assert.deepEqual(queue.enqueued[0]!.payload,{commitId:"commit-1"});
});

test("PgPolicyEnforcer.commit marks the commit committed",async()=>{
  const db=new FakeDb();
  const enforcer=new PgPolicyEnforcer(new FakeCommandQueue() as any,new FakeNodeRepository([]) as any,db as any);
  await enforcer.commit("commit-1");
  assert.match(db.queries[0]!.text,/UPDATE bapc_security_core\.policy_commits SET status='COMMITTED'/);
  assert.deepEqual(db.queries[0]!.values,["commit-1"]);
});

test("PgMeshCommandSink.sever enqueues QUARANTINE for the target node",async()=>{
  const queue=new FakeCommandQueue();
  const sink=new PgMeshCommandSink(queue as any);
  await sink.sever("node-2");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"node-2");
  assert.equal(queue.enqueued[0]!.type,"QUARANTINE");
});

test("PgMeshCommandSink.configure enqueues APPLY_PEERS — not APPLY_WIREGUARD, which would need this node's own private key",async()=>{
  const queue=new FakeCommandQueue();
  const sink=new PgMeshCommandSink(queue as any);
  const node:MeshNode={
    id:"node-3",deviceId:"device-3",wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
    internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
  };
  await sink.configure(node,[
    {nodeId:"peer-1",publicKey:"peer-pubkey",allowedIps:["10.144.0.3/32"],keepaliveSeconds:25,path:"DIRECT"}
  ]);
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"node-3");
  assert.equal(queue.enqueued[0]!.type,"APPLY_PEERS");
  const payload=queue.enqueued[0]!.payload as {peers:Array<{publicKey:string;privateKeyReference?:string}>};
  assert.equal(payload.peers.length,1);
  assert.equal(payload.peers[0]!.publicKey,"peer-pubkey");
  assert.equal(payload.peers[0]!.privateKeyReference,undefined);
});
