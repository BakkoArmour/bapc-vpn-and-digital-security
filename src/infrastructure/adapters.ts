import type { MeshNode, NetworkPolicy, SecurityEvent } from "../domain/types.js";
// AllowAttestation moved to src/infrastructure/attestation/providers.ts as
// DevelopmentAttestationProvider, alongside the real Windows TPM/Linux TPM2/
// Apple Secure Enclave providers it now has to be explicitly (and
// production-refused) selected from — see AttestationVerifierFactory there.
export class DevelopmentCertificateIssuer {async issueNodeCertificate(nodeId:string,_publicKey:string,ttlMinutes:number){return {serial:`dev-${nodeId}`,certificatePem:"DEVELOPMENT-ONLY",expiresAt:new Date(Date.now()+ttlMinutes*60_000)}}async revoke(){} }
export class NoopPeerDistributor {async configure(_node:MeshNode,_peers:MeshNode[]){}async remove(_nodeId:string){} }
// Dev-only scaffold, superseded by PgPolicyEnforcer in production — still a
// real, widely-used PolicyEnforcer test fixture across tests/integration/**
// (diagnostics-clearance, soc-backend, pg-threat-action-port, threat-engine-
// integration), so this stays. targetedNodeIds is always empty since this
// fake never tracked a node registry at all.
export class InMemoryEnforcer {staged=new Map<string,NetworkPolicy[]>();isolated=new Set<string>();async stage(id:string,p:NetworkPolicy[]){this.staged.set(id,p);return {targetedNodeIds:[] as string[]};}async commit(id:string){this.staged.delete(id)}async rollback(id:string){this.staged.delete(id)}async isolateNode(id:string){this.isolated.add(id)}async restoreNode(id:string){this.isolated.delete(id)}}
// HealthyProbe (an always-true ConnectivityProbe fake) was removed here:
// its only user was tests/core.test.ts, retired in favor of the more
// thorough SafeApplyService test suite (tests/integration/policy/
// safe-apply.test.ts), which already covers "commits on a healthy probe"
// more completely with a purpose-built fake.
export class MemoryBus {events:Array<{topic:string,event:unknown}>=[];async publish(topic:string,event:unknown){this.events.push({topic,event})}}
export class NoopThreatSink {async notify(_e:SecurityEvent){}}
