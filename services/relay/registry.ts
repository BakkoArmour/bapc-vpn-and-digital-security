export interface RelayRecord {
  id:string;region:string;endpoint:string;loadPercent:number;latencyMs:number;
  available:boolean;lastHeartbeat:Date;capacityMbps:number;activeSessions:number;
}
export class RelayRegistry {
  private relays=new Map<string,RelayRecord>();
  heartbeat(r:RelayRecord){this.relays.set(r.id,{...r,lastHeartbeat:new Date(r.lastHeartbeat)});}
  choose(region:string,now=new Date()){
    return [...this.relays.values()]
      .filter(r=>r.available&&now.getTime()-r.lastHeartbeat.getTime()<45_000)
      .filter(r=>r.loadPercent<90&&r.activeSessions<r.capacityMbps*20)
      .sort((a,b)=>{
        const ar=a.region===region?100:0,br=b.region===region?100:0;
        return (br-b.latencyMs-b.loadPercent)-(ar-a.latencyMs-a.loadPercent);
      })[0];
  }
  snapshot(){return [...this.relays.values()].map(x=>({...x}));}
}
