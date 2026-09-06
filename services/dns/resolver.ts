import {DnsProtectionService} from "../../src/application/dns-protection.js";
export interface DnsUpstream {
  resolve(name:string,type:"A"|"AAAA"|"TXT"|"MX"):Promise<Array<{type:string,value:string;ttl:number}>>;
}
export interface DnsAudit {
  record(event:{at:Date;nameHash:string;action:string;reason:string}):Promise<void>;
}
export class SecureDnsResolver {
  constructor(
    private protection:DnsProtectionService,private upstreams:DnsUpstream[],
    private audit:DnsAudit,private sinkholeV4="10.144.0.53"
  ){}
  async resolve(name:string,type:"A"|"AAAA"|"TXT"|"MX"){
    const decision=await this.protection.evaluate(name);
    // Audit logging must never be able to take down DNS resolution itself —
    // a threat-blocking service going fully offline because its audit sink
    // (Postgres) had a blip is a worse outcome than briefly losing audit
    // visibility. This used to be an unguarded `await`, so any audit-write
    // failure propagated out of resolve() and turned every single query
    // (even ones that don't need blocking) into a hard failure.
    try{
      await this.audit.record({
        at:new Date(),nameHash:this.protection.queryFingerprint(name),
        action:decision.action,reason:decision.reason
      });
    }catch(error){
      console.error(JSON.stringify({
        event:"dns.audit_failed",
        error:error instanceof Error?error.message:String(error)
      }));
    }
    if(decision.action==="SINKHOLE"){
      if(type==="A")return [{type:"A",value:this.sinkholeV4,ttl:30}];
      if(type==="AAAA")return [{type:"AAAA",value:"fd14:4b41:5043::53",ttl:30}];
      return [];
    }
    let last:unknown;
    for(const upstream of this.upstreams){
      try{return await upstream.resolve(decision.normalizedDomain,type);}
      catch(error){last=error;}
    }
    throw last??new Error("all encrypted DNS upstreams failed");
  }
}
