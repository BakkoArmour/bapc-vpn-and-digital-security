import type { SecurityEvent, ThreatLevel } from "../domain/types.js";
import type { CertificateIssuer, EventBus, PolicyEnforcer, ThreatSink } from "../ports/infrastructure.js";
import type { DeviceRepository, EventRepository, JitRepository, NodeRepository } from "../ports/repositories.js";

export interface ClearanceVerifier {
  verify(token:string, nodeId:string, now:Date):Promise<{approvedBy:string; caseId:string}>;
}
// A format-only fallback: confirms the token at least claims to be a
// Diagnostics clearance, but performs no cryptographic verification. Only
// suitable for local development — see integrations/diagnostics-clearance.ts
// for the real signature-verifying implementation.
export class FormatOnlyClearanceVerifier implements ClearanceVerifier {
  async verify(token:string,_nodeId:string,_now:Date){
    if(!token.startsWith("diag-clearance:"))throw new Error("signed Diagnostics clearance required");
    return {approvedBy:"unverified",caseId:"unverified"};
  }
}

export class ThreatResponseService {
 constructor(private events:EventRepository,private devices:DeviceRepository,private nodes:NodeRepository,private jit:JitRepository,private enforce:PolicyEnforcer,private certs:CertificateIssuer,private bus:EventBus,private sink:ThreatSink,private clearance:ClearanceVerifier=new FormatOnlyClearanceVerifier()){}
 score(event:SecurityEvent):ThreatLevel {const n=Number(event.metadata.score??0);if(event.severity==="EMERGENCY"||n>=90)return 3;if(event.severity==="CRITICAL"||n>=70)return 2;if(event.severity==="WARN"||n>=40)return 1;return 0;}
 async handle(event:SecurityEvent){await this.events.append(event);await this.sink.notify(event);const level=this.score(event);if(level===0)return {level,action:"OBSERVE"};if(level===1){await this.bus.publish("security.challenge.required",{nodeId:event.nodeId});return {level,action:"REAUTHENTICATE"};}if(!event.nodeId)return {level,action:"MANUAL_REVIEW"};
  const node=await this.nodes.get(event.nodeId);if(!node)return {level,action:"UNKNOWN_NODE"};const device=await this.devices.get(node.deviceId);if(device){await this.devices.save({...device,compromised:true,updatedAt:event.at,quarantineReason:event.description});}
  const grants=await this.jit.listActive(event.at);for(const g of grants.filter(x=>x.targetZone===node.zone)){await this.jit.save({...g,terminated:true,terminationReason:"security incident"});}
  await this.enforce.isolateNode(node.id);await this.bus.publish("diagnostics.forensic_access.ready",{nodeId:node.id,deviceId:node.deviceId,level});return {level,action:"QUARANTINED"};
 }
 async restore(nodeId:string,clearanceToken:string,now=new Date()){
  const approved=await this.clearance.verify(clearanceToken,nodeId,now);
  const node=await this.nodes.get(nodeId);if(!node)throw new Error("node not found");
  const device=await this.devices.get(node.deviceId);if(device){const{quarantineReason:_,...cleared}=device;await this.devices.save({...cleared,compromised:false,updatedAt:now});}
  await this.enforce.restoreNode(nodeId);
  await this.bus.publish("security.node.restored",{nodeId,approvedBy:approved.approvedBy,caseId:approved.caseId});
 }
}
