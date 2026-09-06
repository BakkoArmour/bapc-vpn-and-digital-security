import type {NetworkPolicy} from "../domain/types.js";
import type {PolicyEnforcer} from "../ports/infrastructure.js";
import type {NodeRepository} from "../ports/repositories.js";
import type {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";
import {PolicyCompiler} from "../application/policy-compiler.js";

const firewallRulesFor=(policies:NetworkPolicy[])=>policies.map(p=>({
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
// stage/rollback broadcast a real APPLY_FIREWALL/ROLLBACK_FIREWALL command to
// every currently-active node via the same durable command queue the REST
// endpoint-agent heartbeat drains and executes against the real
// PlatformAdapter (agents/shared/production-agent.ts) — previously
// InMemoryEnforcer just tracked staged policies in a Map with zero effect on
// any real node, so SafeApplyService's "auto-rollback if this broke
// connectivity" safety net had nothing to actually roll back. commit needs
// no further node-facing action: the rules are already live from stage: it
// just clears the bookkeeping used to decide what a rollback removes.
//
// isolateNode/restoreNode is the path ThreatResponseService and SOC
// emergency lockdown actually call to cut a specific node off — this
// persists "QUARANTINE"/"RESTORE", the command types ProductionAgent.execute
// actually implements (PlatformAdapter.isolate/restore, no secret material
// involved), not the mesh.proto ControllerCommand.Action names.
export class PgPolicyEnforcer implements PolicyEnforcer {
  private staged=new Map<string,NetworkPolicy[]>();
  private compiler=new PolicyCompiler();
  constructor(private queue:PgCommandQueue,private nodes:NodeRepository){}

  async stage(commitId:string,policies:NetworkPolicy[]):Promise<void>{
    // PolicyCompiler existed fully built and tested (invalid zone/port
    // rejection) with no caller anywhere — a policy with a typo'd zone name
    // or an out-of-range port would previously be broadcast to every node's
    // APPLY_FIREWALL command as-is, only to fail unpredictably at whatever
    // native nft/WFP call actually tried to apply it. This validates before
    // anything is ever sent, using the same compiler the platform-specific
    // (linux/windows/apple) enforcement-plan methods already assume valid
    // input for.
    this.compiler.compile(policies);
    this.staged.set(commitId,policies);
    const rules=firewallRulesFor(policies);
    for(const node of await this.nodes.list()){
      await this.queue.enqueue(node.id,"APPLY_FIREWALL",{commitId,defaultAction:"DENY",rules});
    }
  }

  async commit(commitId:string):Promise<void>{
    this.staged.delete(commitId);
  }

  async rollback(commitId:string):Promise<void>{
    this.staged.delete(commitId);
    for(const node of await this.nodes.list()){
      await this.queue.enqueue(node.id,"ROLLBACK_FIREWALL",{commitId},200);
    }
  }

  async isolateNode(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"QUARANTINE",{reason:"policy enforcement point"},200);
  }
  async restoreNode(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"RESTORE",{},200);
  }
}
