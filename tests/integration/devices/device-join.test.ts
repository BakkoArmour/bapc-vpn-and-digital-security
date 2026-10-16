import test from "node:test";
import assert from "node:assert/strict";
import {MemoryInvites, GATEWAY, deviceRequest} from "./join-fakes.js";
import {
  DeviceJoinService, generateInviteCode, hashInviteCode, normalizeInviteCode, mintInvite,
  type VpnGatewayConfig
} from "../../../src/application/device-join.js";
import {EnrollmentService} from "../../../src/application/enrollment.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {NoopPeerDistributor} from "../../../src/infrastructure/adapters.js";
import {WindowsTpmAttestationProvider} from "../../../src/infrastructure/attestation/providers.js";
import {PgEnrollmentInviteStore} from "../../../src/infrastructure/pg-enrollment-invites.js";
import {AuthorizationError, ValidationError, ConflictError} from "../../../src/domain/errors.js";
import {loadConfig} from "../../../src/config.js";
import {asHttpError} from "../../../src/api/rest/errors.js";

// The public join path end to end, against the REAL Windows TPM verifier
// (not the allow-all development provider): the device builds a genuine
// signed attestation envelope bound to its CSR's identity key, exactly the
// way installers/windows/join-vpn.ps1 does with a TPM-resident key.

const setup=(gateway:VpnGatewayConfig|null=GATEWAY)=>{
  const store=new MemoryStore(),invites=new MemoryInvites(),clock=new SystemClock();
  const certs={issueNodeCertificate:async(nodeId:string)=>({serial:nodeId,certificatePem:"CERT",expiresAt:new Date()}),revoke:async()=>{}};
  const enrollment=new EnrollmentService(store,store,store,new WindowsTpmAttestationProvider(),certs,new NoopPeerDistributor(),new RandomIds(),clock);
  return {store,invites,service:new DeviceJoinService(invites,enrollment,store,gateway??undefined,clock)};
};

test("invite codes are 120-bit Crockford base32 and normalize forgivingly",()=>{
  const code=generateInviteCode();
  assert.match(code,/^BAPC-[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{6}){3}$/);
  assert.equal(hashInviteCode(code.toLowerCase().replace(/-/g," ")),hashInviteCode(code));
  assert.equal(hashInviteCode(code.slice(5)),hashInviteCode(code));
  assert.equal(normalizeInviteCode("bapc-0000O0-1111IL-000000-000000"),"000000111111000000000000");
  assert.notEqual(generateInviteCode(),code);
});

test("a device with a valid invite and genuine TPM-style evidence joins and gets only the gateway as its peer",async()=>{
  const {store,invites,service}=setup();
  const {code}=await service.mintInvite("owner");
  const result=await service.join(deviceRequest(code));
  assert.equal(result.gateway.publicKey,GATEWAY.publicKey);
  assert.deepEqual(result.gateway.allowedIps,["0.0.0.0/0","::/0"]);
  assert.equal(result.addresses.ipv4,"10.144.10.3");
  assert.equal(store.nodes.get(result.nodeId)?.internalIpv4,"10.144.10.3");
  const row=[...invites.rows.values()][0]!;
  assert.equal(row.nodeId,result.nodeId);
  assert.ok(row.usedAt);
});

test("an invite works exactly once",async()=>{
  const {service}=setup();
  const {code}=await service.mintInvite("owner");
  await service.join(deviceRequest(code));
  await assert.rejects(service.join(deviceRequest(code,{hardwareUuid:"other-hw"})),AuthorizationError);
});

test("an unknown or expired invite is refused",async()=>{
  const {invites,service}=setup();
  await assert.rejects(service.join(deviceRequest(generateInviteCode())),AuthorizationError);
  const {code}=await service.mintInvite("owner",{hours:1});
  [...invites.rows.values()][0]!.expiresAt=new Date(Date.now()-1000);
  await assert.rejects(service.join(deviceRequest(code)),AuthorizationError);
});

test("failed attestation is refused and gives the invite back",async()=>{
  const {invites,service}=setup();
  const {code}=await service.mintInvite("owner");
  await assert.rejects(service.join(deviceRequest(code,{tamper:true})),ValidationError);
  assert.equal([...invites.rows.values()][0]!.usedAt,null);
  await service.join(deviceRequest(code));
});

test("an empty attestation quote is refused before the invite is touched",async()=>{
  const {invites,service}=setup();
  const {code}=await service.mintInvite("owner");
  await assert.rejects(service.join({...deviceRequest(code),attestationQuote:""}),ValidationError);
  assert.equal([...invites.rows.values()][0]!.usedAt,null);
});

test("the same hardware can't join twice",async()=>{
  const {service}=setup();
  await service.join(deviceRequest((await service.mintInvite("owner")).code));
  await assert.rejects(service.join(deviceRequest((await service.mintInvite("owner")).code)),ConflictError);
});

test("nobody can join while no gateway is configured",async()=>{
  const {service}=setup(null);
  await assert.rejects(service.join(deviceRequest("BAPC-000000-000000-000000-000000")),/not configured/);
});

test("the gateway peer list leaves out revoked and compromised devices",async()=>{
  const {store,service}=setup();
  const a=await service.join(deviceRequest((await service.mintInvite("owner")).code,{hardwareUuid:"hw-a"}));
  const b=await service.join(deviceRequest((await service.mintInvite("owner")).code,{hardwareUuid:"hw-b"}));
  const deviceB=store.devices.get(store.nodes.get(b.nodeId)!.deviceId)!;
  store.devices.set(deviceB.id,{...deviceB,revoked:true});
  const peers=await service.gatewayPeers(store);
  assert.deepEqual(peers.map(p=>p.nodeId),[a.nodeId]);
  assert.deepEqual(peers[0]!.allowedIps,[`${a.addresses.ipv4}/32`,`${a.addresses.ipv6}/128`]);
});

test("invite lifetimes are bounded",async()=>{
  await assert.rejects(mintInvite(new MemoryInvites(),new SystemClock(),"owner",{hours:0}),ValidationError);
  await assert.rejects(mintInvite(new MemoryInvites(),new SystemClock(),"owner",{hours:24*30}),ValidationError);
});

test("PgEnrollmentInviteStore.claim is a single conditional update",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgEnrollmentInviteStore({query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}});
  assert.equal(await store.claim("hash",new Date(0)),null);
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.enrollment_invites SET used_at=\$2/);
  assert.match(queries[0]!.text,/used_at IS NULL AND expires_at>\$2/);
  await store.release("inv");
  assert.match(queries[1]!.text,/used_by_node IS NULL/);
});

test("loadConfig reads the VPN gateway only when it's fully and validly configured",()=>{
  assert.equal(loadConfig({}).vpnGateway,undefined);
  const gw=loadConfig({VPN_GATEWAY_PUBLIC_KEY:GATEWAY.publicKey,VPN_GATEWAY_ENDPOINT:"116.203.78.222:51820"}).vpnGateway;
  assert.deepEqual(gw,{publicKey:GATEWAY.publicKey,endpoint:"116.203.78.222:51820",ipv4:"10.144.0.1",ipv6:"fd14:4b41:5043::1",dns:["1.1.1.1","1.0.0.1"]});
  assert.throws(()=>loadConfig({VPN_GATEWAY_ENDPOINT:"116.203.78.222:51820"}),/VPN_GATEWAY_PUBLIC_KEY/);
  assert.throws(()=>loadConfig({VPN_GATEWAY_PUBLIC_KEY:GATEWAY.publicKey,VPN_GATEWAY_ENDPOINT:"no-port"}),/VPN_GATEWAY_ENDPOINT/);
});

test("join refusals reach the device as clear 4xx errors, not an opaque 500",()=>{
  assert.equal(asHttpError(new AuthorizationError("invite code is not valid")).status,403);
  assert.equal(asHttpError(new ConflictError("hardware already enrolled")).status,409);
  assert.equal(asHttpError(new ValidationError("hardware attestation failed")).status,400);
  assert.equal(asHttpError(new Error("boom")).status,500);
});
