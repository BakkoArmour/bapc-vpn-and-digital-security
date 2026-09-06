export interface EgressGateway {
  id:string;region:string;fixedIp:string;healthy:boolean;loadPercent:number;lastCheck:Date;
}
export class EgressSelector {
  select(gateways:EgressGateway[],preferredRegion:string,now=new Date()){
    const healthy=gateways.filter(g=>g.healthy&&now.getTime()-g.lastCheck.getTime()<30_000&&g.loadPercent<95);
    const selected=healthy.sort((a,b)=>{
      const pa=a.region===preferredRegion?100:0,pb=b.region===preferredRegion?100:0;
      return (pb-b.loadPercent)-(pa-a.loadPercent);
    })[0];
    if(!selected)throw new Error("no healthy egress gateway");
    return selected;
  }
}
