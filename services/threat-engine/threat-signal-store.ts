import type {ThreatSignal} from "./engine.js";

// The persistence boundary ThreatCorrelator was missing entirely — its
// sliding-window signal accumulation lived only in a process-local Map, so a
// control-plane restart erased every un-escalated signal a node had built up
// so far. InMemoryThreatSignalStore below preserves the old in-memory
// behavior (and is ThreatCorrelator's default, so existing callers/tests
// that never cared about persistence are unaffected); PgThreatSignalStore
// (pg-threat-signal-store.ts) is the real one production wires up.
export interface ThreatSignalStore {
  record(nodeKey:string,signal:ThreatSignal):Promise<void>;
  // Returns every signal for nodeKey at or after sinceMs, pruning (deleting/
  // discarding) anything older as a side effect — the one query
  // ThreatCorrelator.ingest needs per call.
  window(nodeKey:string,sinceMs:number):Promise<ThreatSignal[]>;
  // Deletes every signal for nodeKey and returns how many there were.
  clear(nodeKey:string):Promise<number>;
}

export class InMemoryThreatSignalStore implements ThreatSignalStore {
  private windows=new Map<string,ThreatSignal[]>();
  async record(nodeKey:string,signal:ThreatSignal){
    const kept=this.windows.get(nodeKey)??[];
    kept.push(signal);
    this.windows.set(nodeKey,kept);
  }
  async window(nodeKey:string,sinceMs:number){
    const kept=(this.windows.get(nodeKey)??[]).filter(s=>s.at.getTime()>=sinceMs);
    if(kept.length)this.windows.set(nodeKey,kept); else this.windows.delete(nodeKey);
    return kept;
  }
  async clear(nodeKey:string){
    const count=(this.windows.get(nodeKey)??[]).length;
    this.windows.delete(nodeKey);
    return count;
  }
}
