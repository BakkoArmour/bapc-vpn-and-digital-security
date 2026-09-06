// A tiny, dependency-free Prometheus text-exposition-format counter/gauge
// registry — enough for the control plane's own request/error/latency
// counters without pulling in prom-client for a handful of metrics.
export class MetricsRegistry {
  private counters=new Map<string,number>();
  private labelSets=new Map<string,Map<string,number>>();

  incr(name:string,by=1){this.counters.set(name,(this.counters.get(name)??0)+by);}

  incrLabeled(name:string,labels:Record<string,string>,by=1){
    const key=Object.entries(labels).sort(([a],[b])=>a.localeCompare(b))
      .map(([k,v])=>`${k}="${v}"`).join(",");
    const set=this.labelSets.get(name)??new Map<string,number>();
    set.set(key,(set.get(key)??0)+by);
    this.labelSets.set(name,set);
  }

  render():string{
    const lines:string[]=[];
    for(const [name,value] of this.counters){
      lines.push(`# TYPE ${name} counter`,`${name} ${value}`);
    }
    for(const [name,set] of this.labelSets){
      lines.push(`# TYPE ${name} counter`);
      for(const [labels,value] of set)lines.push(`${name}{${labels}} ${value}`);
    }
    return lines.join("\n")+"\n";
  }
}

export const metrics=new MetricsRegistry();
