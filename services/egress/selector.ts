export interface EgressGateway {
  id:string;region:string;fixedIp:string;healthy:boolean;loadPercent:number;lastCheck:Date;
  // Real capacity/utilization/connectivity signals — previously nothing
  // tracked these at all (egress-server.ts hardcoded loadPercent:0 and
  // there was no latency, session count, or utilization concept).
  latencyMs:number;activeSessions:number;capacityPercent:number;
}
export class EgressSelector {
  select(gateways:EgressGateway[],preferredRegion:string,now=new Date()){
    const healthy=gateways.filter(g=>
      g.healthy&&now.getTime()-g.lastCheck.getTime()<30_000&&g.loadPercent<95&&g.capacityPercent<95
    );
    const selected=healthy.sort((a,b)=>{
      const pa=a.region===preferredRegion?100:0,pb=b.region===preferredRegion?100:0;
      // capacityPercent weighted more heavily than raw load/latency — a
      // gateway near its session ceiling degrades every existing
      // connection, not just new ones (mirrors RelayRoutingService).
      const scoreA=pa-a.loadPercent-a.latencyMs*0.1-a.capacityPercent*2;
      const scoreB=pb-b.loadPercent-b.latencyMs*0.1-b.capacityPercent*2;
      return scoreB-scoreA;
    })[0];
    if(!selected)throw new Error("no healthy egress gateway");
    return selected;
  }
}
