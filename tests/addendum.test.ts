import test from "node:test";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {HmacBearerGuard} from "../src/api/rest/guard.js";
import {AddressAllocator,MeshController} from "../services/mesh-controller/controller.js";
import {ThreatEngine} from "../services/threat-engine/engine.js";
import {EgressSelector} from "../services/egress/selector.js";

test("bearer guard validates role",()=>{
  const secret="x".repeat(32),encoded=Buffer.from(JSON.stringify({
    sub:"owner",roles:["security-read"],exp:Math.floor(Date.now()/1000)+60
  })).toString("base64url");
  const sig=createHmac("sha256",secret).update(encoded).digest("base64url");
  const req={headers:{authorization:`Bearer ${encoded}.${sig}`}} as any;
  assert.equal(new HmacBearerGuard(secret).verify(req,["security-read"]).sub,"owner");
});

test("allocator skips used addresses",async()=>{
  const a=new AddressAllocator({
    usedIpv4:async()=>new Set(["10.144.10.3"]),
    usedIpv6:async()=>new Set(["fd14:4b41:5043::2"])
  });
  const lease=await a.next();
  assert.ok(lease.ipv4.startsWith("10.144."));
  assert.ok(lease.ipv6.startsWith("fd14:4b41:5043::"));
});

test("mesh quarantine severs node",async()=>{
  let severed="";
  const c=new MeshController({configure:async()=>{},sever:async id=>{severed=id;}});
  await c.quarantine("node-1");
  assert.equal(severed,"node-1");
});

test("threat engine contains critical node",async()=>{
  const actions:string[]=[];
  const engine=new ThreatEngine({
    reauthenticate:async()=>{actions.push("reauth");},
    terminateJit:async()=>{actions.push("jit");},
    isolate:async()=>{actions.push("isolate");},
    revokeNodeCertificates:async()=>{actions.push("revoke");},
    rotateMeshIdentity:async()=>{actions.push("rotate");},
    restore:async()=>{actions.push("restore");}
  },{
    open:async()=>{},event:async()=>{}
  });
  const result=await engine.evaluate([
    {nodeId:"n1",kind:"malware",confidence:1,weight:70,at:new Date(),metadata:{}}
  ]);
  assert.equal(result.severity,"CRITICAL");
  assert.deepEqual(actions,["jit","isolate"]);
});

test("egress selector fails closed",()=>{
  assert.throws(()=>new EgressSelector().select([],"us-east"));
});
