export interface RelayHealth {
  id:string;region:string;endpoint:string;latencyMs:number;loadPercent:number;
  available:boolean;lastHeartbeat:Date;
  // Real capacity/utilization signals — previously nothing tracked these at
  // all (relay-server.ts hardcoded loadPercent:0/latencyMs:0 and there was
  // no concept of session count or utilization anywhere).
  activeSessions:number;capacityPercent:number;throughputBytesPerSec:number;
}
export interface PathCandidate {kind:"DIRECT"|"LOCAL_RELAY"|"REGIONAL_RELAY";endpoint:string;score:number;}
export class RelayRoutingService {
  // `local` and `regional` are caller-partitioned (see MeshController.
  // selectRelayEndpoint, the only real caller): every relay whose own region
  // matches the requesting node's region goes in `local` and scores in the
  // LOCAL_RELAY tier above every REGIONAL_RELAY candidate, regardless of
  // individual latency/load — a same-region hop is assumed better-placed
  // than a healthier-looking but geographically distant one. This only
  // claims a tiering by known region, never a real measured latency
  // improvement this architecture has no way to observe.
  select(directEndpoint:string|undefined,local:RelayHealth[],regional:RelayHealth[],now=new Date()):PathCandidate[]{
    const out:PathCandidate[]=[];
    if(directEndpoint)out.push({kind:"DIRECT",endpoint:directEndpoint,score:1000});
    for(const r of local.filter(x=>this.healthy(x,now)))out.push({kind:"LOCAL_RELAY",endpoint:r.endpoint,score:800-this.penalty(r)});
    for(const r of regional.filter(x=>this.healthy(x,now)))out.push({kind:"REGIONAL_RELAY",endpoint:r.endpoint,score:600-this.penalty(r)});
    return out.sort((a,b)=>b.score-a.score);
  }
  // capacityPercent (real utilization: activeSessions against an operator-
  // configured ceiling — see RELAY_MAX_SESSIONS in src/runtime/relay-server.ts)
  // is weighted more heavily than raw latency/CPU load: a relay approaching
  // its session ceiling degrades every existing session, not just new ones.
  private penalty(r:RelayHealth){return r.latencyMs+r.loadPercent+r.capacityPercent*2;}
  private healthy(r:RelayHealth,now:Date){
    return r.available&&now.getTime()-r.lastHeartbeat.getTime()<45_000&&r.loadPercent<95&&r.capacityPercent<95;
  }
}
