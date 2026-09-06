import { createHash } from "node:crypto";
export interface DnsThreatFeed { contains(domain:string):Promise<boolean>; }
export interface DnsDecision { action:"ALLOW"|"SINKHOLE"; normalizedDomain:string; reason:string; sinkholeAddress?:string; }
const normalize=(d:string)=>d.trim().toLowerCase().replace(/\.$/,"");
export class DnsProtectionService {constructor(private feeds:DnsThreatFeed[],private sinkhole="10.144.0.53"){}
 async evaluate(domain:string):Promise<DnsDecision>{const d=normalize(domain);if(!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d))return{action:"SINKHOLE",normalizedDomain:d,reason:"invalid or suspicious domain",sinkholeAddress:this.sinkhole};for(const f of this.feeds)if(await f.contains(d))return{action:"SINKHOLE",normalizedDomain:d,reason:"threat-feed match",sinkholeAddress:this.sinkhole};const label=d.split(".")[0]??"";const entropyLike=label.length>24&&new Set(label).size/label.length>.55;if(entropyLike)return{action:"SINKHOLE",normalizedDomain:d,reason:"possible domain-generation algorithm",sinkholeAddress:this.sinkhole};return{action:"ALLOW",normalizedDomain:d,reason:"no threat match"};}
 queryFingerprint(domain:string){return createHash("sha256").update(normalize(domain)).digest("hex");}}
