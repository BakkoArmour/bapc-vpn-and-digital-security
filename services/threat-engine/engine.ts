import {randomUUID} from "node:crypto";
export type ThreatSeverity="INFO"|"WARN"|"CRITICAL"|"EMERGENCY";
export interface ThreatSignal {
  nodeId?:string;kind:string;confidence:number;weight:number;at:Date;metadata:Record<string,unknown>;
}
export interface ThreatActionPort {
  reauthenticate(nodeId:string):Promise<void>;
  terminateJit(nodeId:string):Promise<void>;
  isolate(nodeId:string,reason:string):Promise<void>;
  revokeNodeCertificates(nodeId:string,reason:string):Promise<void>;
  rotateMeshIdentity(nodeId:string):Promise<void>;
  restore(nodeId:string):Promise<void>;
}
export interface IncidentPort {
  open(input:{id:string;nodeId?:string;severity:ThreatSeverity;score:number;signals:ThreatSignal[]}):Promise<void>;
  event(input:{severity:ThreatSeverity;type:string;description:string;metadata:Record<string,unknown>}):Promise<void>;
}
export class ThreatEngine {
  constructor(private actions:ThreatActionPort,private incidents:IncidentPort){}
  score(signals:ThreatSignal[]){
    const raw=signals.reduce((n,s)=>n+(Math.max(0,Math.min(1,s.confidence))*Math.max(0,s.weight)),0);
    return Math.min(100,Math.round(raw));
  }
  async evaluate(signals:ThreatSignal[]){
    const score=this.score(signals);
    const severity:ThreatSeverity=score>=85?"EMERGENCY":score>=65?"CRITICAL":score>=35?"WARN":"INFO";
    const nodeId=signals.find(s=>s.nodeId)?.nodeId;
    await this.incidents.open({id:randomUUID(),...(nodeId?{nodeId}:{}),severity,score,signals});
    if(nodeId&&severity==="WARN")await this.actions.reauthenticate(nodeId);
    if(nodeId&&severity==="CRITICAL"){
      await this.actions.terminateJit(nodeId);
      await this.actions.isolate(nodeId,"critical threat score");
    }
    if(nodeId&&severity==="EMERGENCY"){
      await this.actions.terminateJit(nodeId);
      await this.actions.isolate(nodeId,"emergency threat score");
      await this.actions.revokeNodeCertificates(nodeId,"emergency containment");
      await this.actions.rotateMeshIdentity(nodeId);
    }
    await this.incidents.event({
      severity,type:"THREAT_EVALUATED",description:`threat score ${score}`,
      metadata:{score,signalCount:signals.length,nodeId:nodeId??null}
    });
    return {score,severity,contained:Boolean(nodeId&&score>=65)};
  }
  async restore(nodeId:string,approvedBy:string,forensicClearance:boolean){
    if(!forensicClearance)throw new Error("forensic clearance required before restore");
    if(approvedBy.trim().length<3)throw new Error("restore approver required");
    await this.actions.restore(nodeId);
    await this.incidents.event({
      severity:"INFO",type:"NODE_RESTORED",description:"node restored after forensic clearance",
      metadata:{nodeId,approvedBy}
    });
  }
}
