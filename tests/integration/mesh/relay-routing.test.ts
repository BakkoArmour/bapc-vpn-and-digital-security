import test from "node:test";
import assert from "node:assert/strict";
import {MeshController} from "../../../services/mesh-controller/controller.js";
import type {MeshNode} from "../../../src/domain/types.js";
import type {RelayHealth} from "../../../src/application/relay-routing.js";

// RelayRoutingService existed fully built and tested with no caller
// anywhere — reconcile's relayEndpoint parameter had no real supplier
// before this, so mesh topology was always DIRECT even when a healthy
// relay was actually registered. This proves MeshController now actually
// asks for and uses real candidate data — and that an explicit
// relayEndpoint argument still wins outright (backward compatible).

const node=(id:string):MeshNode=>({
  id,deviceId:`device-${id}`,wireGuardPublicKey:`pk-${id}`,internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true
});
const relay=(overrides:Partial<RelayHealth>):RelayHealth=>({
  id:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",latencyMs:20,loadPercent:10,
  available:true,lastHeartbeat:new Date(),activeSessions:5,capacityPercent:10,throughputBytesPerSec:1000,
  ...overrides
});

test("reconcile stays DIRECT when no relaySource is configured (unchanged default)",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController({configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}});
  await controller.reconcile(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls[0][0].path,"DIRECT");
});

test("reconcile stays DIRECT when a relaySource exists but has no healthy candidates",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController(
    {configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}},
    {candidates:async()=>[]}
  );
  await controller.reconcile(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls[0][0].path,"DIRECT");
});

test("reconcile routes through the best real relay candidate when one exists",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController(
    {configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}},
    {candidates:async()=>[relay({id:"slow",latencyMs:200,loadPercent:80}),relay({id:"fast",latencyMs:5,loadPercent:5})]}
  );
  await controller.reconcile(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls[0][0].path,"RELAY");
  assert.equal(configureCalls[0][0].endpoint,"203.0.113.10:51900"); // both candidates share this fixture endpoint
});

test("a relay at or above 95% capacity is excluded even if latency/load are fine",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController(
    {configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}},
    {candidates:async()=>[relay({capacityPercent:95})]}
  );
  await controller.reconcile(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls[0][0].path,"DIRECT");
});

test("candidate selection prefers lower capacity utilization over marginally better latency",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController(
    {configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}},
    {candidates:async()=>[
      relay({id:"busy",endpoint:"busy.example:51900",latencyMs:5,loadPercent:5,capacityPercent:80}),
      relay({id:"idle",endpoint:"idle.example:51900",latencyMs:15,loadPercent:5,capacityPercent:5})
    ]}
  );
  await controller.reconcile(node("a"),[node("a"),node("b")]);
  assert.equal(configureCalls[0][0].endpoint,"idle.example:51900");
});

test("an explicit relayEndpoint argument still wins outright over relaySource candidates",async()=>{
  const configureCalls:any[]=[];
  const controller=new MeshController(
    {configure:async(n,peers)=>{configureCalls.push(peers);},sever:async()=>{}},
    {candidates:async()=>[relay({endpoint:"203.0.113.10:51900"})]}
  );
  await controller.reconcile(node("a"),[node("a"),node("b")],"override.example:51900");
  assert.equal(configureCalls[0][0].path,"RELAY");
  assert.equal(configureCalls[0][0].endpoint,"override.example:51900");
});
