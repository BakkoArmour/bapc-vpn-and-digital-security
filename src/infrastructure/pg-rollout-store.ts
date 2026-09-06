import type {NodeRolloutRecord, RolloutStore} from "../ports/infrastructure.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// Backs policy_rollout_nodes (db/018_policy_rollout_nodes.sql) — the real
// per-node verification SafeApplyService uses instead of trusting the
// control plane's own database health alone.
export class PgRolloutStore implements RolloutStore {
  constructor(private db:PgQueryable){}

  async start(commitId:string,nodeIds:string[]):Promise<void>{
    for(const nodeId of nodeIds){
      await this.db.query(
        `INSERT INTO bapc_security_core.policy_rollout_nodes(commit_id,node_id,status)
         VALUES($1,$2,'PENDING') ON CONFLICT(commit_id,node_id) DO NOTHING`,
        [commitId,nodeId]
      );
    }
  }

  // Pulls the real command_acknowledgements rows for this rollout's
  // APPLY_FIREWALL commands (matched by the commitId echoed back in
  // ProductionAgent's acknowledgement — see production-agent.ts) and
  // advances any still-PENDING row to SUCCEEDED/FAILED accordingly. A
  // command_acknowledgements status of anything other than SUCCEEDED
  // (FAILED, or the ambiguous ACKNOWLEDGED a result with no boolean `ok`
  // produces) is treated as FAILED here — a rollout's safety decision
  // should never treat "we're not sure" as success.
  async refresh(commitId:string):Promise<NodeRolloutRecord[]>{
    const acks=await this.db.query(
      `SELECT node_id,status,acknowledged_at,details FROM bapc_security_core.command_acknowledgements
       WHERE command_type='APPLY_FIREWALL' AND details->>'commitId'=$1`,
      [commitId]
    );
    for(const row of acks.rows){
      const status=row.status==="SUCCEEDED"?"SUCCEEDED":"FAILED";
      await this.db.query(
        `UPDATE bapc_security_core.policy_rollout_nodes SET status=$3,acknowledged_at=$4,details=$5
         WHERE commit_id=$1 AND node_id=$2 AND status='PENDING'`,
        [commitId,row.node_id,status,row.acknowledged_at,row.details]
      );
    }
    return this.summary(commitId);
  }

  async finalizeTimeouts(commitId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.policy_rollout_nodes SET status='TIMED_OUT' WHERE commit_id=$1 AND status='PENDING'`,
      [commitId]
    );
  }

  // PolicyEnforcer.rollback broadcasts ROLLBACK_FIREWALL to every active
  // node regardless of that node's own prior status (including nodes that
  // had already SUCCEEDED — fleet-wide consistency beats letting some nodes
  // keep a policy others were reverted from), so every row's final state
  // becomes ROLLED_BACK together, not just the ones that failed.
  async markRolledBack(commitId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.policy_rollout_nodes SET status='ROLLED_BACK' WHERE commit_id=$1`,
      [commitId]
    );
  }

  async summary(commitId:string):Promise<NodeRolloutRecord[]>{
    const r=await this.db.query(
      `SELECT node_id,status,acknowledged_at,details FROM bapc_security_core.policy_rollout_nodes WHERE commit_id=$1`,
      [commitId]
    );
    return r.rows.map(row=>({
      nodeId:row.node_id,status:row.status,
      ...(row.acknowledged_at?{acknowledgedAt:new Date(row.acknowledged_at)}:{}),
      details:typeof row.details==="string"?JSON.parse(row.details):row.details
    }));
  }
}
