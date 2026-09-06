import dnsPacket from "dns-packet";
import type {DnsUpstream} from "./resolver.js";

// Real DNS-over-HTTPS (RFC 8484) upstream: encodes a standard DNS query,
// POSTs it as application/dns-message, and decodes the wire-format response.
// Works against any RFC 8484-compliant resolver (Cloudflare, Google, etc.).
export class DohUpstream implements DnsUpstream {
  constructor(private endpoint="https://cloudflare-dns.com/dns-query",private timeoutMs=5_000){}
  async resolve(name:string,type:"A"|"AAAA"|"TXT"|"MX"){
    const query=dnsPacket.encode({
      type:"query",id:Math.floor(Math.random()*65536),
      flags:dnsPacket.RECURSION_DESIRED,
      questions:[{type,name}]
    });
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),this.timeoutMs);
    try{
      const res=await fetch(this.endpoint,{
        method:"POST",
        headers:{"content-type":"application/dns-message","accept":"application/dns-message"},
        body:new Uint8Array(query),
        signal:controller.signal
      });
      if(!res.ok)throw new Error(`DoH upstream ${this.endpoint} returned ${res.status}`);
      const body=Buffer.from(await res.arrayBuffer());
      const decoded=dnsPacket.decode(body);
      return (decoded.answers??[])
        .filter(a=>a.type===type)
        .map(a=>({type:a.type,value:String((a as any).data),ttl:(a as any).ttl??60}));
    }finally{
      clearTimeout(timeout);
    }
  }
}
