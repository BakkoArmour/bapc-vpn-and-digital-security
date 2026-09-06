import type {NodeRolloutRecord, RolloutStore} from "../ports/infrastructure.js";

// SafeApplyService's default RolloutStore when none is supplied — keeps
// every existing caller/test that never cared about per-node rollout
// tracking working unchanged (mirrors ThreatCorrelator's
// InMemoryThreatSignalStore default). Never wired up in production:
// real per-node status comes only from command_acknowledgements, so
// production always supplies PgRolloutStore instead.
export class InMemoryRolloutStore implements RolloutStore {
  private rows=new Map<string,Map<string,NodeRolloutRecord>>();
  async start(commitId:string,nodeIds:string[]){
    const rows=new Map<string,NodeRolloutRecord>();
    for(const nodeId of nodeIds)rows.set(nodeId,{nodeId,status:"PENDING",details:{}});
    this.rows.set(commitId,rows);
  }
  async refresh(commitId:string){return this.summary(commitId);}
  async finalizeTimeouts(commitId:string){
    for(const row of this.rows.get(commitId)?.values()??[])
      if(row.status==="PENDING")row.status="TIMED_OUT";
  }
  async markRolledBack(commitId:string){
    for(const row of this.rows.get(commitId)?.values()??[])row.status="ROLLED_BACK";
  }
  async summary(commitId:string){return [...(this.rows.get(commitId)?.values()??[])];}
}
