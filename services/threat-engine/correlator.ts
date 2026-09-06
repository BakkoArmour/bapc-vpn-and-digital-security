import type {ThreatEngine, ThreatSignal} from "./engine.js";

export interface DismissalPort {
  record(nodeId:string,dismissedBy:string,signalCount:number):Promise<void>;
}

// Individual signals (a failed auth, a scan hit, an odd packet-rate sample)
// are rarely dangerous alone — ThreatEngine.evaluate scores whatever batch
// it's handed, so correlating repeated low-confidence signals over TIME into
// one growing batch per node is what turns "5 failed logins in 2 minutes"
// into an actual CRITICAL evaluation instead of 5 separate INFO results.
export class ThreatCorrelator {
  private windows=new Map<string,ThreatSignal[]>();
  constructor(private engine:ThreatEngine,private windowMs=300_000,private dismissals?:DismissalPort){}

  private prune(nodeId:string,now:number){
    const kept=(this.windows.get(nodeId)??[]).filter(s=>now-s.at.getTime()<this.windowMs);
    if(kept.length)this.windows.set(nodeId,kept); else this.windows.delete(nodeId);
    return kept;
  }

  async ingest(signal:ThreatSignal){
    const nodeId=signal.nodeId??"__unattributed__";
    const now=signal.at.getTime();
    const kept=this.prune(nodeId,now);
    kept.push(signal);
    this.windows.set(nodeId,kept);
    return this.engine.evaluate(kept);
  }

  // An operator (or automated review) confirms the accumulated signals for a
  // node were a false positive: the correlation window resets so those
  // signals stop contributing to future scores, and the dismissal itself is
  // recorded for audit/tuning (not silently discarded).
  async dismiss(nodeId:string,dismissedBy:string){
    const count=(this.windows.get(nodeId)??[]).length;
    this.windows.delete(nodeId);
    await this.dismissals?.record(nodeId,dismissedBy,count);
    return {clearedSignals:count};
  }

  activeSignalCount(nodeId:string,now=new Date()){
    return this.prune(nodeId,now.getTime()).length;
  }
}
