import {createHash} from "node:crypto";
import type {MeshNode,SecurityZone} from "../../src/domain/types.js";
import {RelayRoutingService, type RelayHealth} from "../../src/application/relay-routing.js";

export interface RelayCandidateSource {candidates():Promise<RelayHealth[]>;}

export interface AddressLeaseStore {
  usedIpv4():Promise<Set<string>>;
  usedIpv6():Promise<Set<string>>;
}
export interface MeshCommandSink {
  configure(node:MeshNode,peers:MeshPeerPlan[]):Promise<void>;
  sever(nodeId:string):Promise<void>;
}
export interface MeshPeerPlan {
  nodeId:string;publicKey:string;endpoint?:string;allowedIps:string[];
  keepaliveSeconds:number;path:"DIRECT"|"RELAY";
}
export class AddressAllocator {
  constructor(private leases:AddressLeaseStore){}
  async next(){
    const used4=await this.leases.usedIpv4(),used6=await this.leases.usedIpv6();
    for(let n=2;n<65534;n++){
      const a=10+Math.floor(n/254),b=(n%254)+1;
      const ipv4=`10.144.${a%256}.${b}`;
      const ipv6=`fd14:4b41:5043::${n.toString(16)}`;
      if(!used4.has(ipv4)&&!used6.has(ipv6))return {ipv4,ipv6};
    }
    throw new Error("mesh address pool exhausted");
  }
}
export class MeshController {
  private routing=new RelayRoutingService();
  // relaySource is optional and additive: previously nothing anywhere ever
  // passed a relayEndpoint at all, so reconcile always fell straight to
  // DIRECT regardless of whether a healthy relay existed. An explicit
  // relayEndpoint argument still wins outright when a caller supplies one
  // (unchanged behavior) — this only fills in when one wasn't given.
  constructor(private sink:MeshCommandSink,private relaySource?:RelayCandidateSource){}
  async reconcile(node:MeshNode,all:MeshNode[],relayEndpoint?:string){
    const resolvedRelayEndpoint=relayEndpoint??await this.selectRelayEndpoint();
    const peers=all.filter(p=>p.active&&p.id!==node.id)
      .filter(p=>this.allowed(node.zone,p.zone))
      .map<MeshPeerPlan>(p=>({
        nodeId:p.id,publicKey:p.wireGuardPublicKey,
        allowedIps:[`${p.internalIpv4}/32`,`${p.internalIpv6}/128`],
        keepaliveSeconds:25,path:resolvedRelayEndpoint?"RELAY":"DIRECT",
        ...(resolvedRelayEndpoint?{endpoint:resolvedRelayEndpoint}:{})
      }));
    await this.sink.configure(node,peers);
    return {nodeId:node.id,peerCount:peers.length,
      topologyHash:createHash("sha256").update(JSON.stringify(peers)).digest("hex")};
  }
  // No per-node geographic region exists anywhere in this schema (MeshNode's
  // "zone" is a security classification — ZONE_PROD_APP, ZONE_DEV — not a
  // geography), so there's no real "local" relay to distinguish from
  // "regional" ones. Every healthy relay is scored as a REGIONAL_RELAY
  // candidate; the highest-scoring one wins, or DIRECT if none exist —
  // exactly the prior behavior when no relay was ever available, now
  // correctly extended to prefer a relay once one actually is.
  private async selectRelayEndpoint():Promise<string|undefined>{
    if(!this.relaySource)return undefined;
    const candidates=await this.relaySource.candidates();
    const [best]=this.routing.select(undefined,undefined,candidates);
    return best&&best.kind!=="DIRECT"?best.endpoint:undefined;
  }
  async quarantine(nodeId:string){await this.sink.sever(nodeId);}
  private allowed(a:SecurityZone,b:SecurityZone){
    if(a==="ZONE_FORENSIC_ISOLATION"||b==="ZONE_FORENSIC_ISOLATION")
      return a==="ZONE_ADMIN_MGMT"||b==="ZONE_ADMIN_MGMT";
    if(a==="ZONE_DEV"&&b==="ZONE_PROD_DATA")return false;
    return true;
  }
}
