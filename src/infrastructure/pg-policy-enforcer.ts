import type {NetworkPolicy} from "../domain/types.js";
import type {PolicyEnforcer} from "../ports/infrastructure.js";
import type {NodeRepository} from "../ports/repositories.js";
import type {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {PolicyCompiler} from "../application/policy-compiler.js";

export interface PgQueryable {query(text:string,values?:unknown[]):Promise<{rows:any[]}>;}

// A well-known nil UUID, not a real identity — used only when stage() is
// called with no initiatedBy (policy_commits.initiated_by is NOT NULL, and
// PolicyEnforcer.stage's initiatedBy parameter is optional for compatibility
// with other implementers/tests that don't track one).
const SYSTEM_INITIATOR="00000000-0000-0000-0000-000000000000";

// Exported for NodeReconciliationService (src/application/
// node-reconciliation.ts), which needs to rebuild the exact same firewall
// plan shape to re-deliver it inside a RECONCILE payload's firewallPlan
// field (src/agent/reconciler.ts) when a node drifts, without duplicating
// this compilation logic.
export const firewallRulesFor=(policies:NetworkPolicy[])=>policies.map(p=>({
  id:p.id,
  // ISOLATE-action policies aren't a firewall verb; SafeApplyService/this
  // enforcer's stage/rollback path is for ALLOW/DENY rule sets — a policy
  // meaning "cut this off entirely" belongs to isolateNode below instead, so
  // it's treated the same as DENY here rather than rejected outright.
  action:(p.action==="ALLOW"?"ALLOW":"DENY") as "ALLOW"|"DENY",
  protocols:p.protocols,ports:p.destinationPorts,
  sourceZones:p.sourceZones,destinationZones:p.destinationZones
}));

// Replaces InMemoryEnforcer in production.
//
// stage/commit/rollback now persist to policy_commits
// (db/002_operational_tables.sql) — a table that existed with columns for
// exactly this lifecycle (status STAGED/COMMITTED/ROLLED_BACK,
// auto_revert_seconds, initiated_by, finalized_at) but no write path at
// all; the previous version of this class tracked staged policies in a
// plain in-memory Map whose stored value was never even read back, only
// ever set and later deleted — pure vestigial bookkeeping with no real
// persistence, invisible to any operator and lost on every restart.
//
// stage/rollback also broadcast a real APPLY_FIREWALL/ROLLBACK_FIREWALL
// command to every currently-active node via the same durable command
// queue the REST endpoint-agent heartbeat drains and executes against the
// real PlatformAdapter (agents/shared/production-agent.ts) — previously
// InMemoryEnforcer had zero effect on any real node, so SafeApplyService's
// "auto-rollback if this broke connectivity" safety net had nothing to
// actually roll back. commit needs no further node-facing action: the
// rules are already live from stage.
//
// isolateNode/restoreNode is the path ThreatResponseService and SOC
// emergency lockdown actually call to cut a specific node off — this
// persists "QUARANTINE"/"RESTORE", the command types ProductionAgent.execute
// actually implements (PlatformAdapter.isolate/restore, no secret material
// involved), not the mesh.proto ControllerCommand.Action names.
export class PgPolicyEnforcer implements PolicyEnforcer {
  private compiler=new PolicyCompiler();
  constructor(private queue:PgCommandQueue,private nodes:NodeRepository,private db:PgQueryable){}

  async stage(commitId:string,policies:NetworkPolicy[],initiatedBy?:string):Promise<{targetedNodeIds:string[]}>{
    // PolicyCompiler existed fully built and tested (invalid zone/port
    // rejection) with no caller anywhere — a policy with a typo'd zone name
    // or an out-of-range port would previously be broadcast to every node's
    // APPLY_FIREWALL command as-is, only to fail unpredictably at whatever
    // native nft/WFP call actually tried to apply it. This validates before
    // anything is ever sent, using the same compiler the platform-specific
    // (linux/windows/apple) enforcement-plan methods already assume valid
    // input for.
    this.compiler.compile(policies);
    await this.db.query(
      `INSERT INTO bapc_security_core.policy_commits(commit_id,policy_payload,status,initiated_by)
       VALUES($1,$2,'STAGED',$3)`,
      [commitId,JSON.stringify(policies),initiatedBy??SYSTEM_INITIATOR]
    );
    const rules=firewallRulesFor(policies);
    const nodes=await this.nodes.list();
    for(const node of nodes){
      await this.queue.enqueue(node.id,"APPLY_FIREWALL",{commitId,defaultAction:"DENY",rules});
    }
    // Reported back so SafeApplyService (src/application/safe-apply.ts) can
    // verify each targeted node individually afterward, instead of only
    // checking the control plane's own database health.
    return {targetedNodeIds:nodes.map(n=>n.id)};
  }

  async commit(commitId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.policy_commits SET status='COMMITTED', finalized_at=now() WHERE commit_id=$1`,
      [commitId]
    );
  }

  async rollback(commitId:string):Promise<void>{
    await this.db.query(
      `UPDATE bapc_security_core.policy_commits SET status='ROLLED_BACK', finalized_at=now() WHERE commit_id=$1`,
      [commitId]
    );
    for(const node of await this.nodes.list()){
      await this.queue.enqueue(node.id,"ROLLBACK_FIREWALL",{commitId},200);
    }
  }

  // controller_commands.node_id is a real foreign key into mesh_nodes —
  // correct for the normal case, but ThreatEngine.evaluate calls isolate()
  // for ANY nodeId a threat signal names (see PgThreatActionPort — some of
  // those come from callers other than its own trusted heartbeat path, like
  // POST /api/v1/threats/signal). A stale, mistyped, or since-deleted
  // nodeId there violated the foreign key and crashed the whole request
  // with an opaque 500 — found live against real Postgres, not by any test
  // that mocks db.query. Nothing to isolate/restore for a node that isn't
  // actually enrolled.
  async isolateNode(nodeId:string):Promise<void>{
    if(!await this.nodes.get(nodeId))return;
    await this.queue.enqueue(nodeId,"QUARANTINE",{reason:"policy enforcement point"},200);
  }
  async restoreNode(nodeId:string):Promise<void>{
    if(!await this.nodes.get(nodeId))return;
    await this.queue.enqueue(nodeId,"RESTORE",{},200);
  }
}
