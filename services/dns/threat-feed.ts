import {readFileSync} from "node:fs";
import type {DnsThreatFeed} from "../../src/application/dns-protection.js";

// A minimal, real threat feed: one domain per line in a text file (comments
// with '#', blank lines ignored). Production deployments should replace or
// supplement this with a live commercial/OSINT feed subscription (a
// DnsThreatFeed is just `contains(domain): Promise<boolean>`, so swapping in
// an API-backed feed requires no change to DnsProtectionService).
export class StaticListThreatFeed implements DnsThreatFeed {
  private domains:Set<string>;
  constructor(domains:Iterable<string>){this.domains=new Set([...domains].map(d=>d.toLowerCase()));}
  static fromFile(path:string):StaticListThreatFeed{
    const lines=readFileSync(path,"utf8").split("\n")
      .map(l=>l.trim())
      .filter(l=>l.length>0&&!l.startsWith("#"));
    return new StaticListThreatFeed(lines);
  }
  async contains(domain:string){return this.domains.has(domain.toLowerCase());}
}
