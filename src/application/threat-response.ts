import type { SecurityEvent, ThreatLevel } from "../domain/types.js";
import type { CertificateIssuer, EventBus, PolicyEnforcer, ThreatSink } from "../ports/infrastructure.js";
import type { DeviceRepository, EventRepository, JitRepository, NodeRepository } from "../ports/repositories.js";
export class ThreatResponseService {
 constructor(private events:EventRepository,private devices:DeviceRepository,private nodes:NodeRepository,private jit:JitRepository,private enforce:PolicyEnforcer,private certs:CertificateIssuer,private bus:EventBus,private sink:ThreatSink){}
 score(event:SecurityEvent):ThreatLevel {const n=Number(event.metadata.score??0);if(event.severity==="EMERGENCY"||n>=90)return 3;if(event.severity==="CRITICAL"||n>=70)return 2;if(event.severity==="WARN"||n>=40)return 1;return 0;}
 async handle(event:SecurityEvent){await this.events.append(event);await this.sink.notify(event);const level=this.score(event);if(level===0)return {level,action:"OBSERVE"};if(level===1){await this.bus.publish("security.challenge.required",{nodeId:event.nodeId});return {level,action:"REAUTHENTICATE"};}if(!event.nodeId)return {level,action:"MANUAL_REVIEW"};
  const node=await this.nodes.get(event.nodeId);if(!node)return {level,action:"UNKNOWN_NODE"};const device=await this.devices.get(node.deviceId);if(device){await this.devices.save({...device,compromised:true,updatedAt:event.at});}
  const grants=await this.jit.listActive(event.at);for(const g of grants.filter(x=>x.targetZone===node.zone)){await this.jit.save({...g,terminated:true,terminationReason:"security incident"});}
  await this.enforce.isolateNode(node.id);await this.bus.publish("diagnostics.forensic_access.ready",{nodeId:node.id,deviceId:node.deviceId,level});return {level,action:"QUARANTINED"};
 }
 async restore(nodeId:string,clearanceToken:string){if(!clearanceToken.startsWith("diag-clearance:"))throw new Error("signed Diagnostics clearance required");const node=await this.nodes.get(nodeId);if(!node)throw new Error("node not found");const device=await this.devices.get(node.deviceId);if(device)await this.devices.save({...device,compromised:false,updatedAt:new Date()});await this.enforce.restoreNode(nodeId);await this.bus.publish("security.node.restored",{nodeId});}
}
