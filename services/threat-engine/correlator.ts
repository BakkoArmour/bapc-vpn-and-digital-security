import type {ThreatEngine, ThreatSignal} from "./engine.js";
import {InMemoryThreatSignalStore, type ThreatSignalStore} from "./threat-signal-store.js";

export interface DismissalPort {
  record(nodeId:string,dismissedBy:string,signalCount:number):Promise<void>;
}

const UNATTRIBUTED="__unattributed__";

// Individual signals (a failed auth, a scan hit, an odd packet-rate sample)
// are rarely dangerous alone — ThreatEngine.evaluate scores whatever batch
// it's handed, so correlating repeated low-confidence signals over TIME into
// one growing batch per node is what turns "5 failed logins in 2 minutes"
// into an actual CRITICAL evaluation instead of 5 separate INFO results.
//
// The sliding window itself is delegated to `store` (threat-signal-store.ts)
// rather than kept in a local Map — it defaults to an in-memory store (so
// every existing caller/test that never cared about persistence keeps
// working unchanged), but production wires up PgThreatSignalStore so a
// control-plane restart doesn't silently erase a node's un-escalated
// signal history along with it.
export class ThreatCorrelator {
  constructor(
    private engine:ThreatEngine,private windowMs=300_000,private dismissals?:DismissalPort,
    private store:ThreatSignalStore=new InMemoryThreatSignalStore()
  ){}

  async ingest(signal:ThreatSignal){
    const nodeKey=signal.nodeId??UNATTRIBUTED;
    await this.store.record(nodeKey,signal);
    const kept=await this.store.window(nodeKey,signal.at.getTime()-this.windowMs);
    return this.engine.evaluate(kept);
  }

  // An operator (or automated review) confirms the accumulated signals for a
  // node were a false positive: the correlation window resets so those
  // signals stop contributing to future scores, and the dismissal itself is
  // recorded for audit/tuning (not silently discarded).
  async dismiss(nodeId:string,dismissedBy:string){
    const count=await this.store.clear(nodeId);
    await this.dismissals?.record(nodeId,dismissedBy,count);
    await this.engine.resolveIncidents(nodeId,dismissedBy);
    return {clearedSignals:count};
  }

  async activeSignalCount(nodeId:string,now=new Date()){
    return (await this.store.window(nodeId,now.getTime()-this.windowMs)).length;
  }
}
