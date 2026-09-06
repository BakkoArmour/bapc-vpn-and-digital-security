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
    await this.audit.record({
      at:new Date(),nameHash:this.protection.queryFingerprint(name),
      action:decision.action,reason:decision.reason
    });
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
