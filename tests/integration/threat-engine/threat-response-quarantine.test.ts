import test from "node:test";
import assert from "node:assert/strict";
import {ThreatResponseService} from "../../../src/application/threat-response.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {InMemoryEnforcer, DevelopmentCertificateIssuer, NoopThreatSink, MemoryBus} from "../../../src/infrastructure/adapters.js";
import type {Device, MeshNode, SecurityEvent} from "../../../src/domain/types.js";

// devices.quarantine_reason had no write path at all before this —
// ThreatResponseService.handle marked a device compromised with no record
// of *why*, and restore() never cleared it back out.

const setup=async()=>{
  const store=new MemoryStore();
  const device:Device={id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux",osVersion:"1",
    compromised:false,revoked:false,
    posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
    createdAt:new Date(),updatedAt:new Date()};
  const node:MeshNode={id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",
    listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true};
  await store.save(device);await store.save(node);
  const threatResponse=new ThreatResponseService(
    store,store,store,store,new InMemoryEnforcer(),new DevelopmentCertificateIssuer(),
    new MemoryBus(),new NoopThreatSink()
  );
  return {store,threatResponse};
};

const criticalEvent=(overrides:Partial<SecurityEvent> = {}):SecurityEvent=>({
  id:"e1",nodeId:"n1",at:new Date(),severity:"CRITICAL",engine:"test",type:"test.signal",
  description:"five failed auth attempts in 60s",metadata:{},...overrides
});

test("ThreatResponseService.handle records the triggering event's description as quarantineReason",async()=>{
  const {store,threatResponse}=await setup();
  const result=await threatResponse.handle(criticalEvent());
  assert.equal(result.action,"QUARANTINED");
  const device=await store.devices.get("d1");
  assert.equal(device?.quarantineReason,"five failed auth attempts in 60s");
});

test("ThreatResponseService.restore clears quarantineReason once cleared",async()=>{
  const {store,threatResponse}=await setup();
  await threatResponse.handle(criticalEvent());
  await threatResponse.restore("n1","diag-clearance:anything");
  const device=await store.devices.get("d1");
  assert.equal(device?.compromised,false);
  assert.equal(device?.quarantineReason,undefined);
});
