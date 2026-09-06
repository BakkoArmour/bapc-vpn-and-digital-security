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

// Mirrors db/012_forensic_isolation_diagnostics_policy.sql's default policy
// exactly, closing the gap docs/INCIDENT-RESPONSE-RUNBOOK.md called out: this
// proves an approved investigator, connecting from an admin-management-zone
// node with an active JIT grant, can actually reach a quarantined node's
// forensic-isolation-zone data — and that nobody else can.
test("the default forensic-isolation diagnostics policy allows a JIT-approved security-approver from ZONE_ADMIN_MGMT, and default-denies everyone else",async()=>{
  const store=new MemoryStore();
  await store.save({
    id:"p1",name:"default-forensic-isolation-diagnostics-access",
    sourceZones:["ZONE_ADMIN_MGMT"],destinationZones:["ZONE_FORENSIC_ISOLATION"],
    protocols:["ANY"],destinationPorts:[],action:"ALLOW",requiredRoles:["security-approver"],
    requiresJit:true,priority:100,version:1,active:true
  });
  const pd=new PolicyDecisionService(store,store,new RandomIds(),new SystemClock(),new HmacDecisionSigner(SECRET));
  const investigator=identity({roles:["security-approver"]});
  const investigatorNode=node({zone:"ZONE_ADMIN_MGMT"});
  const forensicResource=resource({resource:"quarantined-node-1",zone:"ZONE_FORENSIC_ISOLATION",protocol:"TCP",port:8443});

  const withoutJit=await pd.decide(investigator,goodDevice(),investigatorNode,forensicResource);
  assert.equal(withoutJit.decision.allowed,false);
  assert.equal(withoutJit.decision.reason,"active JIT grant required");

  const now=new Date();
  await store.save({
    id:"g1",userId:"u1",targetResource:"quarantined-node-1",targetZone:"ZONE_FORENSIC_ISOLATION",
    justification:"investigating a compromised node",grantedAt:now,expiresAt:new Date(now.getTime()+60_000),terminated:false
  });
  const withJit=await pd.decide(investigator,goodDevice(),investigatorNode,forensicResource);
  assert.equal(withJit.decision.allowed,true);

  const wrongRole=await pd.decide(identity({roles:["engineer"]}),goodDevice(),investigatorNode,forensicResource);
  assert.equal(wrongRole.decision.allowed,false);
  assert.equal(wrongRole.decision.reason,"default deny");

  const wrongSourceZone=await pd.decide(investigator,goodDevice(),node({zone:"ZONE_DEV"}),forensicResource);
  assert.equal(wrongSourceZone.decision.allowed,false);
  assert.equal(wrongSourceZone.decision.reason,"default deny");
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

// AUTH_REFRESH_MS (config.ts) had no consumer at all — every access
// decision got a hard-coded 30-second expiry regardless of what an
// operator configured.
test("decision.expiresAt uses the configured authorizationRefreshMs, not a hard-coded 30 seconds",async()=>{
  const store=new MemoryStore();
  const now=new Date("2026-01-01T00:00:00.000Z");
  const clock={now:()=>now};
  const pd=new PolicyDecisionService(store,store,new RandomIds(),clock,new HmacDecisionSigner(SECRET),120_000);
  const {decision}=await pd.decide(identity({mfa:false}),goodDevice(),node(),resource());
  assert.equal(decision.expiresAt.getTime(),now.getTime()+120_000);
});

test("decision.expiresAt defaults to a 30-second window when the caller doesn't configure one",async()=>{
  const store=new MemoryStore();
  const now=new Date("2026-01-01T00:00:00.000Z");
  const clock={now:()=>now};
  const pd=new PolicyDecisionService(store,store,new RandomIds(),clock,new HmacDecisionSigner(SECRET));
  const {decision}=await pd.decide(identity({mfa:false}),goodDevice(),node(),resource());
  assert.equal(decision.expiresAt.getTime(),now.getTime()+30_000);
});
