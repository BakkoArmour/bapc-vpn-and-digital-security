import test from "node:test";
import assert from "node:assert/strict";
import {PgPolicyEnforcer} from "../../../src/infrastructure/pg-policy-enforcer.js";
import {PgMeshCommandSink} from "../../../services/mesh-controller/pg-mesh-command-sink.js";
import type {MeshNode} from "../../../src/domain/types.js";

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

test("PgPolicyEnforcer.isolateNode enqueues QUARANTINE, the type ProductionAgent.execute implements",async()=>{
  const queue=new FakeCommandQueue();
  const enforcer=new PgPolicyEnforcer(queue as any);
  await enforcer.isolateNode("node-1");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"node-1");
  assert.equal(queue.enqueued[0]!.type,"QUARANTINE");
});

test("PgPolicyEnforcer.restoreNode enqueues RESTORE, the type ProductionAgent.execute implements",async()=>{
  const queue=new FakeCommandQueue();
  const enforcer=new PgPolicyEnforcer(queue as any);
  await enforcer.restoreNode("node-1");
  assert.equal(queue.enqueued[0]!.type,"RESTORE");
});

test("PgMeshCommandSink.sever enqueues QUARANTINE for the target node",async()=>{
  const queue=new FakeCommandQueue();
  const sink=new PgMeshCommandSink(queue as any);
  await sink.sever("node-2");
  assert.equal(queue.enqueued.length,1);
  assert.equal(queue.enqueued[0]!.nodeId,"node-2");
  assert.equal(queue.enqueued[0]!.type,"QUARANTINE");
});

test("PgMeshCommandSink.configure enqueues nothing (no safe way to deliver a peer list without the node's own private key)",async()=>{
  const queue=new FakeCommandQueue();
  const sink=new PgMeshCommandSink(queue as any);
  const node:MeshNode={
    id:"node-3",deviceId:"device-3",wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
    internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
  };
  await sink.configure(node,[]);
  assert.equal(queue.enqueued.length,0);
});
