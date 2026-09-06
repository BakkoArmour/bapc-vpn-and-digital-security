import type { MeshNode, NetworkPolicy, SecurityEvent } from "../domain/types.js";
export class AllowAttestation {async verify(){return true;}}
export class DevelopmentCertificateIssuer {async issueNodeCertificate(nodeId:string,_publicKey:string,ttlMinutes:number){return {serial:`dev-${nodeId}`,certificatePem:"DEVELOPMENT-ONLY",expiresAt:new Date(Date.now()+ttlMinutes*60_000)}}async revoke(){} }
export class NoopPeerDistributor {async configure(_node:MeshNode,_peers:MeshNode[]){}async remove(_nodeId:string){} }
export class InMemoryEnforcer {staged=new Map<string,NetworkPolicy[]>();isolated=new Set<string>();async stage(id:string,p:NetworkPolicy[]){this.staged.set(id,p)}async commit(id:string){this.staged.delete(id)}async rollback(id:string){this.staged.delete(id)}async isolateNode(id:string){this.isolated.add(id)}async restoreNode(id:string){this.isolated.delete(id)}}
export class HealthyProbe {async verifyControlPlane(){return true;}} export class MemoryBus {events:Array<{topic:string,event:unknown}>=[];async publish(topic:string,event:unknown){this.events.push({topic,event})}}
export class NoopThreatSink {async notify(_e:SecurityEvent){}}
