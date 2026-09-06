import test from "node:test";
import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import dnsPacket from "dns-packet";
import {DnsProtectionService} from "../../../src/application/dns-protection.js";
import {SecureDnsResolver, type DnsAudit, type DnsUpstream} from "../../../services/dns/resolver.js";
import {BapcDnsServer} from "../../../services/dns/dns-server.js";

const query=(port:number,name:string,type:"A"|"AAAA"="A")=>new Promise<any>((resolve,reject)=>{
  const socket=createSocket("udp4");
  const timer=setTimeout(()=>{socket.close();reject(new Error("DNS query timed out"));},2000);
  socket.on("message",msg=>{clearTimeout(timer);socket.close();resolve(dnsPacket.decode(msg));});
  socket.on("error",reject);
  const packet=dnsPacket.encode({type:"query",id:42,flags:dnsPacket.RECURSION_DESIRED,questions:[{type,name}]});
  socket.send(packet,port,"127.0.0.1");
});

const startTestServer=async(upstream:DnsUpstream)=>{
  const events:any[]=[];
  const audit:DnsAudit={async record(e){events.push(e);}};
  const protection=new DnsProtectionService([{async contains(d){return d==="malicious.example";}}]);
  const resolver=new SecureDnsResolver(protection,[upstream],audit,"10.144.0.53");
  const server=new BapcDnsServer(resolver);
  await server.start(0,"127.0.0.1");
  const port=(server.address() as any).port;
  return {server,port,events};
};

test("resolves an allowed domain via the upstream",async()=>{
  const upstream:DnsUpstream={async resolve(){return [{type:"A",value:"93.184.216.34",ttl:60}];}};
  const {server,port,events}=await startTestServer(upstream);
  try{
    const response=await query(port,"example.com");
    assert.equal(response.rcode,"NOERROR");
    assert.equal((response.answers[0] as any).data,"93.184.216.34");
    assert.equal(events[0].action,"ALLOW");
  }finally{await server.stop();}
});

test("sinkholes a threat-feed domain instead of querying upstream",async()=>{
  let upstreamCalled=false;
  const upstream:DnsUpstream={async resolve(){upstreamCalled=true;return [];}};
  const {server,port,events}=await startTestServer(upstream);
  try{
    const response=await query(port,"malicious.example");
    assert.equal((response.answers[0] as any).data,"10.144.0.53");
    assert.equal(upstreamCalled,false);
    assert.equal(events[0].action,"SINKHOLE");
    assert.equal(events[0].reason,"threat-feed match");
  }finally{await server.stop();}
});

test("sinkholes a malformed domain name",async()=>{
  const upstream:DnsUpstream={async resolve(){return [];}};
  const {server,port}=await startTestServer(upstream);
  try{
    // Underscores are valid in a DNS wire-format label but rejected by
    // DnsProtectionService's stricter hostname pattern, so this exercises
    // the "invalid or suspicious domain" sinkhole path specifically.
    const response=await query(port,"bad_domain_label.example");
    assert.equal((response.answers[0] as any).data,"10.144.0.53");
  }finally{await server.stop();}
});

test("answers SERVFAIL when every upstream fails and the domain is not sinkholed",async()=>{
  const upstream:DnsUpstream={async resolve(){throw new Error("upstream unreachable");}};
  const {server,port}=await startTestServer(upstream);
  try{
    const response=await query(port,"good-domain.example");
    assert.equal(response.rcode,"SERVFAIL");
  }finally{await server.stop();}
});

test("DNS resolution still succeeds when the audit sink is unavailable (regression: an unguarded audit write used to fail the whole query)",async()=>{
  const protection=new DnsProtectionService([]);
  const failingAudit:DnsAudit={async record(){throw new Error("audit database unreachable");}};
  const upstream:DnsUpstream={async resolve(){return [{type:"A",value:"93.184.216.34",ttl:60}];}};
  const resolver=new SecureDnsResolver(protection,[upstream],failingAudit,"10.144.0.53");
  const server=new BapcDnsServer(resolver);
  await server.start(0,"127.0.0.1");
  const port=(server.address() as any).port;
  try{
    const response=await query(port,"example.com");
    assert.equal(response.rcode,"NOERROR");
    assert.equal((response.answers[0] as any).data,"93.184.216.34");
  }finally{await server.stop();}
});
