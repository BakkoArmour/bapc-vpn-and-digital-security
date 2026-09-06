import test from "node:test";
import assert from "node:assert/strict";
import {MeshControllerPeerDistributor} from "../../../services/mesh-controller/mesh-controller-peer-distributor.js";
import {MeshController} from "../../../services/mesh-controller/controller.js";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {DevelopmentCertificateIssuer} from "../../../src/infrastructure/adapters.js";
import {DevelopmentAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";
import type {MeshNode} from "../../../src/domain/types.js";

// NoopPeerDistributor meant an already-active node never learned about a
// peer that joined after it did — only the NEW node's own initial peer list
// (returned synchronously in registerNode's response) ever reflected
// reality. This proves the replacement actually reconciles every
// already-active peer against the complete set including the new node.

const node=(id:string,zone:MeshNode["zone"]="ZONE_PROD_APP"):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone,active:true
});

test("configure reconciles every existing peer against the full set including the new node",async()=>{
  const configureCalls:Array<{nodeId:string;peerIds:string[]}>=[];
  const controller=new MeshController({
    configure:async(n,peers)=>{configureCalls.push({nodeId:n.id,peerIds:peers.map(p=>p.nodeId)});},
    sever:async()=>{}
  });
  const distributor=new MeshControllerPeerDistributor(controller);
  const newNode=node("new"),existing1=node("existing-1"),existing2=node("existing-2");

  await distributor.configure(newNode,[existing1,existing2]);

  assert.equal(configureCalls.length,2);
  assert.deepEqual(configureCalls.map(c=>c.nodeId).sort(),["existing-1","existing-2"]);
  const forExisting1=configureCalls.find(c=>c.nodeId==="existing-1")!;
  assert.ok(forExisting1.peerIds.includes("new"),"existing-1 should now have the new node as a peer");
  assert.ok(forExisting1.peerIds.includes("existing-2"));
});

test("configure with no existing peers does nothing (first node in a zone)",async()=>{
  const configureCalls:unknown[]=[];
  const controller=new MeshController({configure:async()=>{configureCalls.push(1);},sever:async()=>{}});
  const distributor=new MeshControllerPeerDistributor(controller);
  await distributor.configure(node("solo"),[]);
  assert.equal(configureCalls.length,0);
});

test("configure respects zone isolation the same way reconcile always has",async()=>{
  const configureCalls:Array<{nodeId:string;peerIds:string[]}>=[];
  const controller=new MeshController({
    configure:async(n,peers)=>{configureCalls.push({nodeId:n.id,peerIds:peers.map(p=>p.nodeId)});},
    sever:async()=>{}
  });
  const distributor=new MeshControllerPeerDistributor(controller);
  const forensicNode=node("forensic-1","ZONE_FORENSIC_ISOLATION");
  const prodNode=node("prod-1","ZONE_PROD_APP");

  await distributor.configure(forensicNode,[prodNode]);

  const forProd=configureCalls.find(c=>c.nodeId==="prod-1")!;
  assert.ok(!forProd.peerIds.includes("forensic-1"),"a forensic-isolation node should not become a normal prod node's peer");
});

// The real end-to-end gap: two nodes enrolling in sequence through the
// actual EnrollmentService, wired the same way grpc-server.ts wires it.
// With NoopPeerDistributor, node A would never learn node B exists — only
// B's own registerNode response (which A never sees) would include A.
test("a second node enrolling notifies the first node via MeshController.reconcile",async()=>{
  const store=new MemoryStore();
  const configureCalls:Array<{nodeId:string;peerPublicKeys:string[]}>=[];
  const controller=new MeshController({
    configure:async(n,peers)=>{configureCalls.push({nodeId:n.id,peerPublicKeys:peers.map(p=>p.publicKey)});},
    sever:async()=>{}
  });
  const enrollment=new EnrollmentService(
    store,store,store,new DevelopmentAttestationProvider(),new DevelopmentCertificateIssuer(),
    new MeshControllerPeerDistributor(controller),new RandomIds(),new SystemClock()
  );

  const nodeA=await enrollment.register({
    hostname:"node-a",hardwareId:"hw-a",platform:"linux",osVersion:"linux",
    attestationQuote:new Uint8Array(),attestationPublicKey:"pub-a",
    wireGuardPublicKey:"wg-a",internalIpv4:"10.144.0.2",internalIpv6:"fd14::2",zone:"ZONE_PROD_APP"
  });
  // Nothing has told node A about anyone yet — it's the only node.
  assert.equal(configureCalls.length,0);

  const nodeB=await enrollment.register({
    hostname:"node-b",hardwareId:"hw-b",platform:"linux",osVersion:"linux",
    attestationQuote:new Uint8Array(),attestationPublicKey:"pub-b",
    wireGuardPublicKey:"wg-b",internalIpv4:"10.144.0.3",internalIpv6:"fd14::3",zone:"ZONE_PROD_APP"
  });

  // Node B's own initial peer list (in its registerNode response) already
  // includes A — that part always worked. The fix is that A gets told too.
  assert.ok(nodeB.peers.some(p=>p.id===nodeA.node.id));
  assert.equal(configureCalls.length,1);
  assert.equal(configureCalls[0]!.nodeId,nodeA.node.id);
  assert.ok(configureCalls[0]!.peerPublicKeys.includes("wg-b"),"node A should now have node B as a peer");
});
