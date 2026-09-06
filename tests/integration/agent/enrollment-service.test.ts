import test from "node:test";
import assert from "node:assert/strict";
import {EnrollmentService, type EnrollmentRequest} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {DevelopmentAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";

// CERTIFICATE_TTL_MINUTES (config.ts) was loaded and validated with nothing
// anywhere that ever read it — every enrollment certificate got a
// hard-coded 1440-minute TTL regardless of what an operator configured.

const request=(overrides:Partial<EnrollmentRequest>={}):EnrollmentRequest=>({
  hostname:"host-1",hardwareId:"hw-1",platform:"linux",osVersion:"6.8",
  attestationQuote:new Uint8Array(0),attestationPublicKey:"pk-identity",
  wireGuardPublicKey:"wg-pk-1",internalIpv4:"10.144.0.2",internalIpv6:"fd14::2",
  zone:"ZONE_PROD_APP",...overrides
});

test("EnrollmentService.register issues a certificate using the configured TTL, not a hard-coded default",async()=>{
  const store=new MemoryStore();
  const ttlCalls:number[]=[];
  const certs={
    issueNodeCertificate:async(_nodeId:string,_publicKey:string,ttlMinutes:number)=>{
      ttlCalls.push(ttlMinutes);
      return {serial:"s1",certificatePem:"CERT",expiresAt:new Date()};
    },
    revoke:async()=>{}
  };
  const service=new EnrollmentService(
    store,store,store,new DevelopmentAttestationProvider(),certs,
    new NoopPeerDistributor(),new RandomIds(),new SystemClock(),
    720
  );
  await service.register(request());
  assert.deepEqual(ttlCalls,[720]);
});

test("EnrollmentService.register defaults to a 1440-minute TTL when the caller doesn't configure one",async()=>{
  const store=new MemoryStore();
  const ttlCalls:number[]=[];
  const certs={
    issueNodeCertificate:async(_nodeId:string,_publicKey:string,ttlMinutes:number)=>{
      ttlCalls.push(ttlMinutes);
      return {serial:"s1",certificatePem:"CERT",expiresAt:new Date()};
    },
    revoke:async()=>{}
  };
  const service=new EnrollmentService(
    store,store,store,new DevelopmentAttestationProvider(),certs,
    new NoopPeerDistributor(),new RandomIds(),new SystemClock()
  );
  await service.register(request({hardwareId:"hw-2",wireGuardPublicKey:"wg-pk-2"}));
  assert.deepEqual(ttlCalls,[1440]);
});
