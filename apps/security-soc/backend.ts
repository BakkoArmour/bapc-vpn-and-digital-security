export interface SocData {
  nodes():Promise<unknown[]>;
  incidents():Promise<unknown[]>;
  policies():Promise<unknown[]>;
  jit():Promise<unknown[]>;
  relays():Promise<unknown[]>;
  certificates():Promise<unknown[]>;
  events(limit:number):Promise<unknown[]>;
}
export interface SocActions {
  quarantine(nodeId:string,reason:string,actor:string):Promise<void>;
  restore(nodeId:string,actor:string):Promise<void>;
  emergencyLockdown(reason:string,actor:string,confirmation:string):Promise<void>;
}
export class SecuritySocBackend {
  constructor(private data:SocData,private actions:SocActions){}
  async snapshot(){
    const [nodes,incidents,policies,jit,relays,certificates,events]=await Promise.all([
      this.data.nodes(),this.data.incidents(),this.data.policies(),this.data.jit(),
      this.data.relays(),this.data.certificates(),this.data.events(100)
    ]);
    return {generatedAt:new Date(),nodes,incidents,policies,jit,relays,certificates,events};
  }
  async quarantine(nodeId:string,reason:string,actor:string){
    if(reason.trim().length<12)throw new Error("quarantine reason must be meaningful");
    await this.actions.quarantine(nodeId,reason,actor);
    return {accepted:true,nodeId};
  }
  async emergencyLockdown(reason:string,actor:string,confirmation:string){
    if(confirmation!=="LOCKDOWN")throw new Error("typed LOCKDOWN confirmation required");
    if(reason.trim().length<20)throw new Error("detailed emergency reason required");
    await this.actions.emergencyLockdown(reason,actor,confirmation);
    return {accepted:true,scope:"ecosystem"};
  }
}
