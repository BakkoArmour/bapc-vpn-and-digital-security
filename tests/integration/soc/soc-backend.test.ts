import test from "node:test";
import assert from "node:assert/strict";
import {PgSocData} from "../../../apps/security-soc/pg-soc-data.js";
import {PgSocActions} from "../../../apps/security-soc/pg-soc-actions.js";
import {SecuritySocBackend} from "../../../apps/security-soc/backend.js";
import {ThreatResponseService} from "../../../src/application/threat-response.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {InMemoryEnforcer, DevelopmentCertificateIssuer, NoopThreatSink, MemoryBus} from "../../../src/infrastructure/adapters.js";
import {EcosystemIntegrationService} from "../../../src/application/integrations.js";
import {DiagnosticsClearanceVerifier, issueClearanceToken} from "../../../integrations/diagnostics-clearance.js";

test("PgSocData issues the expected read-only SQL for every dashboard section",async()=>{
  const queries:string[]=[];
  const data=new PgSocData({query:async(text)=>{queries.push(text);return {rows:[]};}});
  await Promise.all([data.nodes(),data.incidents(),data.policies(),data.jit(),data.relays(),data.certificates(),data.revokedCertificates(),data.events(50)]);
  for(const table of ["mesh_nodes","incidents","network_policies","jit_grants","relays","certificates","security_events"]){
    assert.ok(queries.some(q=>q.includes(table)),`expected a query touching ${table}`);
  }
});

// certificates.revocation_reason had no read path anywhere — certificates()
// deliberately excludes revoked rows, so an operator had no way to see why
// a certificate was revoked short of querying Postgres directly.
test("PgSocData.revokedCertificates selects revoked rows with their reason",async()=>{
  const data=new PgSocData({query:async(text)=>({
    rows:[{cert_id:"c1",node_id:"n1",serial_number:"01",subject_dn:"CN=n1",revoked_at:new Date(),revocation_reason:"emergency containment"}]
  })});
  const rows=await data.revokedCertificates();
  assert.equal(rows[0].revocation_reason,"emergency containment");
});

test("SecuritySocBackend.snapshot includes revokedCertificates alongside the active certificate list",async()=>{
  const {backend}=(()=>{
    const store=new MemoryStore();
    const enforcer=new InMemoryEnforcer();
    const bus=new MemoryBus();
    const ecosystem=new EcosystemIntegrationService(secrets,bus);
    const clearance=new DiagnosticsClearanceVerifier(ecosystem);
    const threatResponse=new ThreatResponseService(store,store,store,store,enforcer,new DevelopmentCertificateIssuer(),bus,new NoopThreatSink(),clearance);
    const actions=new PgSocActions(threatResponse,store,store,enforcer,bus,new RandomIds(),new SystemClock());
    return {backend:new SecuritySocBackend({
      nodes:async()=>[],incidents:async()=>[],policies:async()=>[],jit:async()=>[],relays:async()=>[],
      certificates:async()=>[{serial_number:"01",is_revoked:false}],
      revokedCertificates:async()=>[{serial_number:"02",revocation_reason:"key compromised"}],
      events:async()=>[]
    },actions)};
  })();
  const snapshot=await backend.snapshot();
  assert.deepEqual(snapshot.certificates,[{serial_number:"01",is_revoked:false}]);
  assert.deepEqual(snapshot.revokedCertificates,[{serial_number:"02",revocation_reason:"key compromised"}]);
});

const secrets={diagnostics:"diagnostics-secret-at-least-32-characters",headquarters:"x",["cloud-deployment"]:"x",integration:"x"};

const buildBackend=()=>{
  const store=new MemoryStore();
  const ids=new RandomIds(),clock=new SystemClock();
  const enforcer=new InMemoryEnforcer();
  const bus=new MemoryBus();
  const ecosystem=new EcosystemIntegrationService(secrets,bus);
  const clearance=new DiagnosticsClearanceVerifier(ecosystem);
  const threatResponse=new ThreatResponseService(
    store,store,store,store,enforcer,new DevelopmentCertificateIssuer(),bus,new NoopThreatSink(),clearance
  );
  const actions=new PgSocActions(threatResponse,store,store,enforcer,bus,ids,clock);
  const backend=new SecuritySocBackend({
    nodes:async()=>[],incidents:async()=>[],policies:async()=>[],jit:async()=>[],
    relays:async()=>[],certificates:async()=>[],revokedCertificates:async()=>[],events:async()=>[]
  },actions);
  return {store,enforcer,bus,ecosystem,backend};
};

test("emergency lockdown isolates every active node and terminates every active JIT grant",async()=>{
  const {store,enforcer,bus,backend}=buildBackend();
  const now=new Date();
  await store.save({id:"n1",deviceId:"d1",wireGuardPublicKey:"k1",internalIpv4:"10.0.0.1",internalIpv6:"::1",listenPort:1,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});
  await store.save({id:"n2",deviceId:"d2",wireGuardPublicKey:"k2",internalIpv4:"10.0.0.2",internalIpv6:"::2",listenPort:1,nodeType:"SERVER" as const,zone:"ZONE_DEV" as const,active:false});
  await store.save({id:"g1",userId:"u1",targetResource:"r",targetZone:"ZONE_PROD_APP" as const,justification:"x",grantedAt:now,expiresAt:new Date(now.getTime()+60_000),terminated:false});

  const result=await backend.emergencyLockdown("full ecosystem compromise suspected, confirmed by two operators","owner-1","LOCKDOWN");
  assert.equal(result.accepted,true);
  assert.ok(enforcer.isolated.has("n1"));
  assert.equal(enforcer.isolated.has("n2"),false); // inactive node was never active, nothing to isolate

  const grant=await store.grants.get("g1");
  assert.equal(grant?.terminated,true);
  assert.match(grant?.terminationReason??"",/emergency lockdown/);

  assert.ok(bus.events.some(e=>e.topic==="security.emergency_lockdown"));
});

test("emergency lockdown rejects a missing or wrong confirmation string",async()=>{
  const {backend}=buildBackend();
  await assert.rejects(
    ()=>backend.emergencyLockdown("a sufficiently detailed emergency reason here","owner-1","yes please"),
    /LOCKDOWN confirmation required/
  );
});

test("emergency lockdown rejects a vague reason",async()=>{
  const {backend}=buildBackend();
  await assert.rejects(
    ()=>backend.emergencyLockdown("bad stuff","owner-1","LOCKDOWN"),
    /detailed emergency reason required/
  );
});

test("SecuritySocBackend.restore requires a real verified clearance end-to-end",async()=>{
  const {store,ecosystem,backend}=buildBackend();
  await store.save({id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux" as const,osVersion:"1",compromised:true,revoked:false,
    posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
    createdAt:new Date(),updatedAt:new Date()});
  await store.save({id:"n1",deviceId:"d1",wireGuardPublicKey:"k1",internalIpv4:"10.0.0.1",internalIpv6:"::1",listenPort:1,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true});

  await assert.rejects(()=>backend.restore("n1","owner-1","diag-clearance:bogus"),/malformed/);

  const token=issueClearanceToken(ecosystem,{nodeId:"n1",approvedBy:"analyst","caseId":"C1"});
  const result=await backend.restore("n1","owner-1",token);
  assert.equal(result.accepted,true);
  const device=await store.devices.get("d1");
  assert.equal(device?.compromised,false);
});
