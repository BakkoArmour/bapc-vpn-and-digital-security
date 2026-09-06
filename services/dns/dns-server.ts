import dnsPacket from "dns-packet";
import {createSocket, type Socket} from "node:dgram";
import type {SecureDnsResolver} from "./resolver.js";

const SUPPORTED=new Set(["A","AAAA","TXT","MX"]);

// dns-packet's public API takes rcode packed into the low 4 bits of `flags`
// (its own `rcodes` submodule that does this isn't part of its public d.ts).
const RCODE:Record<string,number>={NOERROR:0,FORMERR:1,SERVFAIL:2,NXDOMAIN:3,NOTIMP:4,REFUSED:5};

// A real, wire-protocol UDP DNS server. Every query is routed through
// SecureDnsResolver (threat-feed/DGA sinkhole + encrypted-upstream failover +
// privacy-preserving audit hashing) before an answer is ever sent.
export class BapcDnsServer {
  private socket:Socket|undefined;
  constructor(private resolver:SecureDnsResolver){}

  start(port=53,host="127.0.0.1"):Promise<void>{
    this.socket=createSocket("udp4");
    this.socket.on("message",(msg,rinfo)=>{void this.handle(msg,rinfo.address,rinfo.port);});
    return new Promise((resolve,reject)=>{
      this.socket!.once("error",reject);
      this.socket!.bind(port,host,()=>resolve());
    });
  }

  async stop():Promise<void>{
    return new Promise(resolve=>{
      if(!this.socket)return resolve();
      this.socket.close(()=>resolve());
    });
  }

  address(){return this.socket?.address();}

  private async handle(msg:Buffer,address:string,port:number){
    let query:dnsPacket.Packet;
    try{query=dnsPacket.decode(msg);}catch{return;} // malformed packet: drop silently, like any resolver would
    const question=query.questions?.[0];
    if(!question||!SUPPORTED.has(question.type)){
      this.reply(query,[],address,port,"NOTIMP");
      return;
    }
    try{
      const records=await this.resolver.resolve(question.name,question.type as "A"|"AAAA"|"TXT"|"MX");
      const answers=records.map(r=>({
        type:r.type as any,name:question.name,ttl:r.ttl,
        data:r.type==="TXT"?Buffer.from(r.value):r.value
      }));
      this.reply(query,answers,address,port,"NOERROR");
    }catch{
      this.reply(query,[],address,port,"SERVFAIL");
    }
  }

  private reply(query:dnsPacket.Packet,answers:any[],address:string,port:number,rcode:keyof typeof RCODE){
    const response=dnsPacket.encode({
      type:"response",id:query.id,
      flags:dnsPacket.RECURSION_DESIRED|dnsPacket.RECURSION_AVAILABLE|RCODE[rcode]!,
      questions:query.questions,answers
    });
    this.socket!.send(response,port,address);
  }
}
