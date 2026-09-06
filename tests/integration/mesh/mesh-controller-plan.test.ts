import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {MeshController, applyPeersPayload} from "../../../services/mesh-controller/controller.js";
import {canonicalJson} from "../../../src/infrastructure/canonical-json.js";
import type {MeshNode} from "../../../src/domain/types.js";

// MeshController.planFor is pure (services/mesh-controller/controller.ts) —
// NodeReconciliationService (src/application/node-reconciliation.ts) relies
// on it to check peer-topology drift without resending anything. This pins
// down that (a) calling it never touches the sink, and (b) the topologyHash
// it returns is computed over the exact payload shape PgMeshCommandSink
// actually delivers as APPLY_PEERS, so it can be compared apples-to-apples
// against the hash ProductionAgent.execute echoes back after applying one.

const node=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});

test("planFor never calls the sink",async()=>{
  let configureCalls=0;
  const controller=new MeshController({configure:async()=>{configureCalls++;},sever:async()=>{}});
  await controller.planFor(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls,0);
});

test("planFor's topologyHash matches a hash computed over PgMeshCommandSink's exact APPLY_PEERS payload shape",async()=>{
  const controller=new MeshController({configure:async()=>{},sever:async()=>{}});
  const {peers,topologyHash}=await controller.planFor(node("a"),[node("a"),node("b")]);
  const expected=createHash("sha256").update(canonicalJson(applyPeersPayload(peers))).digest("hex");
  assert.equal(topologyHash,expected);
});

// The real reason this hash uses canonicalJson instead of JSON.stringify:
// ProductionAgent computes its echoed hash after reading the payload back
// out of controller_commands.payload (jsonb), which reorders object keys —
// a differently-ordered-but-identical peer list must still hash the same.
test("planFor's topologyHash is unaffected by object key order (jsonb does not preserve it)",async()=>{
  const controller=new MeshController({configure:async()=>{},sever:async()=>{}});
  const {peers,topologyHash}=await controller.planFor(node("a"),[node("a"),node("b")]);
  const reordered=applyPeersPayload(peers).map(p=>({keepaliveSeconds:p.keepaliveSeconds,allowedIps:p.allowedIps,publicKey:p.publicKey,...(p as any).endpoint?{endpoint:(p as any).endpoint}:{}}));
  const hashOfReordered=createHash("sha256").update(canonicalJson(reordered)).digest("hex");
  assert.equal(topologyHash,hashOfReordered);
});

test("reconcile's returned topologyHash matches planFor's for the same inputs",async()=>{
  const controller=new MeshController({configure:async()=>{},sever:async()=>{}});
  const all=[node("a"),node("b")];
  const planned=await controller.planFor(node("a"),all);
  const reconciled=await controller.reconcile(node("a"),all);
  assert.equal(reconciled.topologyHash,planned.topologyHash);
});
