import test from "node:test";
import assert from "node:assert/strict";
import {PolicyDecisionService} from "../../../src/application/policy.js";
import {HmacDecisionSigner} from "../../../src/infrastructure/hmac-decision-signer.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import type {Device, IdentityContext, MeshNode, ResourceContext} from "../../../src/domain/types.js";

const SECRET="hmac-decision-secret-at-least-32-characters";

const goodDevice=(overrides:Partial<Device> = {}):Device => ({
  id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux",osVersion:"1",compromised:false,revoked:false,
  posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
  createdAt:new Date(),updatedAt:new Date(),...overrides
});
const node=(overrides:Partial<MeshNode> = {}):MeshNode => ({
  id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",
  listenPort:51820,nodeType:"SERVER",zone:"ZONE_DEV",active:true,...overrides
});
const identity=(overrides:Partial<IdentityContext> = {}):IdentityContext => ({
  userId:"u1",roles:["engineer"],attributes:{},mfa:true,sourceIp:"1.2.3.4",...overrides
});
const resource=(overrides:Partial<ResourceContext> = {}):ResourceContext => ({
  resource:"api.internal",zone:"ZONE_PROD_APP",protocol:"TCP",port:443,...overrides
});

test("HmacDecisionSigner produces a verifiable signature and rejects tampering",async()=>{
  const signer=new HmacDecisionSigner(SECRET);
  const decision={allowed:true,action:"ALLOW" as const,reason:"policy x",decisionId:"dec-1",expiresAt:new Date()};
  const signature=await signer.sign(decision);
  assert.equal(await signer.verify(decision,signature),true);
  assert.equal(await signer.verify({...decision,allowed:false},signature),false);
  const otherSigner=new HmacDecisionSigner("a-completely-different-secret-value");
  assert.equal(await otherSigner.verify(decision,signature),false);
});

test("denies with 'MFA required' when identity lacks MFA, before any policy check",async()=>{
  const store=new MemoryStore();
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const {decision}=await pd.decide(identity({mfa:false}),goodDevice(),node(),resource());
  assert.equal(decision.allowed,false);
  assert.equal(decision.reason,"MFA required");
});

test("denies with 'device is not trusted' when posture fails",async()=>{
  const store=new MemoryStore();
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const badDevice=goodDevice({posture:{...goodDevice().posture,diskEncrypted:false}});
  const {decision}=await pd.decide(identity(),badDevice,node(),resource());
  assert.equal(decision.allowed,false);
  assert.equal(decision.reason,"device is not trusted");
});

test("denies when the mesh node itself is inactive",async()=>{
  const store=new MemoryStore();
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const {decision}=await pd.decide(identity(),goodDevice(),node({active:false}),resource());
  assert.equal(decision.allowed,false);
  assert.equal(decision.reason,"device is not trusted");
});

test("allows when a matching ALLOW policy exists and every prior check passes",async()=>{
  const store=new MemoryStore();
  await store.save({
    id:"p1",name:"dev-to-prod-app",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[443],action:"ALLOW",requiredRoles:[],requiresJit:false,
    priority:10,version:1,active:true
  });
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const {decision,signature}=await pd.decide(identity(),goodDevice(),node(),resource());
  assert.equal(decision.allowed,true);
  assert.equal(decision.reason,"policy dev-to-prod-app");
  const signer=new HmacDecisionSigner(SECRET);
  assert.equal(await signer.verify(decision,signature),true);
});

test("a policy that requiresJit denies without an active matching grant, then allows once one exists",async()=>{
  const store=new MemoryStore();
  await store.save({
    id:"p1",name:"jit-gated",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[443],action:"ALLOW",requiredRoles:[],requiresJit:true,
    priority:10,version:1,active:true
  });
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));

  const denied=await pd.decide(identity(),goodDevice(),node(),resource());
  assert.equal(denied.decision.allowed,false);
  assert.equal(denied.decision.reason,"active JIT grant required");

  const now=new Date();
  await store.save({
    id:"g1",userId:"u1",targetResource:"api.internal",targetZone:"ZONE_PROD_APP",
    justification:"investigating an incident",grantedAt:now,expiresAt:new Date(now.getTime()+60_000),terminated:false
  });
  const allowed=await pd.decide(identity(),goodDevice(),node(),resource());
  assert.equal(allowed.decision.allowed,true);
});

test("denies with default-deny when no policy matches the requested resource/zone",async()=>{
  const store=new MemoryStore();
  await store.save({
    id:"p1",name:"unrelated",sourceZones:["ZONE_ADMIN_MGMT"],destinationZones:["ZONE_ADMIN_MGMT"],
    protocols:["ANY"],destinationPorts:[],action:"ALLOW",requiredRoles:[],requiresJit:false,
    priority:10,version:1,active:true
  });
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const {decision}=await pd.decide(identity(),goodDevice(),node(),resource());
  assert.equal(decision.allowed,false);
  assert.equal(decision.reason,"default deny");
});

test("a required role missing from the identity causes the policy to be skipped",async()=>{
  const store=new MemoryStore();
  await store.save({
    id:"p1",name:"admins-only",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
    protocols:["TCP"],destinationPorts:[443],action:"ALLOW",requiredRoles:["security-admin"],
    requiresJit:false,priority:10,version:1,active:true
  });
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const {decision}=await pd.decide(identity({roles:["engineer"]}),goodDevice(),node(),resource());
  assert.equal(decision.allowed,false);
  assert.equal(decision.reason,"default deny");
});
