import test from "node:test";
import assert from "node:assert/strict";
import {EcosystemIntegrationService} from "../../../src/application/integrations.js";
import {ThreatResponseService, FormatOnlyClearanceVerifier} from "../../../src/application/threat-response.js";
import {DiagnosticsClearanceVerifier, issueClearanceToken} from "../../../integrations/diagnostics-clearance.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {InMemoryEnforcer, DevelopmentCertificateIssuer, NoopThreatSink, MemoryBus} from "../../../src/infrastructure/adapters.js";

const secrets={diagnostics:"diagnostics-secret-at-least-32-characters",headquarters:"x",["cloud-deployment"]:"x",integration:"x"};

test("DiagnosticsClearanceVerifier accepts a genuinely signed clearance",async()=>{
  const store=new MemoryStore();
  const ecosystem=new EcosystemIntegrationService(secrets,new MemoryBus());
  const verifier=new DiagnosticsClearanceVerifier(ecosystem);
  const token=issueClearanceToken(ecosystem,{nodeId:"n1",approvedBy:"diagnostics-analyst-7",caseId:"CASE-42"});
  const result=await verifier.verify(token,"n1",new Date());
  assert.equal(result.approvedBy,"diagnostics-analyst-7");
  assert.equal(result.caseId,"CASE-42");
});

test("DiagnosticsClearanceVerifier rejects a token scoped to a different node",async()=>{
  const store=new MemoryStore();
  const ecosystem=new EcosystemIntegrationService(secrets,new MemoryBus());
  const verifier=new DiagnosticsClearanceVerifier(ecosystem);
  const token=issueClearanceToken(ecosystem,{nodeId:"n1",approvedBy:"analyst",caseId:"CASE-1"});
  await assert.rejects(()=>verifier.verify(token,"n2",new Date()),/not scoped to this node/);
});

test("DiagnosticsClearanceVerifier rejects a forged (wrong-secret) token",async()=>{
  const store=new MemoryStore();
  const attackerEcosystem=new EcosystemIntegrationService({...secrets,diagnostics:"wrong-secret-attacker-controlled-value"},new MemoryBus());
  const forged=issueClearanceToken(attackerEcosystem,{nodeId:"n1",approvedBy:"attacker",caseId:"CASE-X"});

  const realEcosystem=new EcosystemIntegrationService(secrets,new MemoryBus());
  const verifier=new DiagnosticsClearanceVerifier(realEcosystem);
  await assert.rejects(()=>verifier.verify(forged,"n1",new Date()),/invalid ecosystem signature/);
});

test("ThreatResponseService.restore only succeeds with a verified clearance",async()=>{
  const store=new MemoryStore();
  const ids=new RandomIds(),clock=new SystemClock();
  const ecosystem=new EcosystemIntegrationService(secrets,new MemoryBus());
  const clearance=new DiagnosticsClearanceVerifier(ecosystem);
  const threatResponse=new ThreatResponseService(
    store,store,store,store,new InMemoryEnforcer(),new DevelopmentCertificateIssuer(),
    new MemoryBus(),new NoopThreatSink(),clearance
  );

  const device={id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux" as const,osVersion:"1",compromised:true,revoked:false,
    posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
    createdAt:new Date(),updatedAt:new Date()};
  const node={id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",listenPort:51820,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true};
  await store.save(device);await store.save(node);

  await assert.rejects(()=>threatResponse.restore("n1","diag-clearance:not-a-real-token"),/malformed/);

  const token=issueClearanceToken(ecosystem,{nodeId:"n1",approvedBy:"analyst-1",caseId:"CASE-9"});
  await threatResponse.restore("n1",token);
  const restoredDevice=await store.devices.get("d1");
  assert.equal(restoredDevice?.compromised,false);
});

test("FormatOnlyClearanceVerifier is a dev-only fallback that still requires the prefix",async()=>{
  const verifier=new FormatOnlyClearanceVerifier();
  await assert.rejects(()=>verifier.verify("not-a-clearance","n1",new Date()),/signed Diagnostics clearance required/);
  const result=await verifier.verify("diag-clearance:anything","n1",new Date());
  assert.equal(result.approvedBy,"unverified");
});
