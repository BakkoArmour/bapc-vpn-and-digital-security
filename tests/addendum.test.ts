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

// HmacBearerGuard previously only verified a token — nothing implemented the
// signing side, so scripts/mint-token.mjs (and docs/OPERATIONS-MANUAL.md's
// "minting a bearer token" instructions) had nothing to call.
test("HmacBearerGuard.mint produces a token verify() accepts",()=>{
  const secret="y".repeat(32);
  const token=HmacBearerGuard.mint({sub:"11111111-1111-1111-1111-111111111111",roles:["security-owner"]},secret);
  const req={headers:{authorization:`Bearer ${token}`}} as any;
  const claims=new HmacBearerGuard(secret).verify(req,["security-owner"]);
  assert.equal(claims.sub,"11111111-1111-1111-1111-111111111111");
  assert.deepEqual(claims.roles,["security-owner"]);
});

test("HmacBearerGuard.mint defaults exp to now+3600s and honors an explicit exp",()=>{
  const secret="y".repeat(32);
  const before=Math.floor(Date.now()/1000);
  const defaulted=HmacBearerGuard.mint({sub:"u1",roles:[]},secret);
  const [encodedDefault]=defaulted.split(".");
  const defaultClaims=JSON.parse(Buffer.from(encodedDefault!,"base64url").toString("utf8"));
  assert.ok(defaultClaims.exp>=before+3600&&defaultClaims.exp<=before+3601);

  const explicit=HmacBearerGuard.mint({sub:"u1",roles:[],exp:before+10},secret);
  const [encodedExplicit]=explicit.split(".");
  const explicitClaims=JSON.parse(Buffer.from(encodedExplicit!,"base64url").toString("utf8"));
  assert.equal(explicitClaims.exp,before+10);
});

test("a token minted with the wrong secret fails verification",()=>{
  const token=HmacBearerGuard.mint({sub:"u1",roles:["security-read"]},"a".repeat(32));
  const req={headers:{authorization:`Bearer ${token}`}} as any;
  assert.throws(()=>new HmacBearerGuard("b".repeat(32)).verify(req,["security-read"]));
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
