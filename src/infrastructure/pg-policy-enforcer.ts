import type {NetworkPolicy} from "../domain/types.js";
import type {PolicyEnforcer} from "../ports/infrastructure.js";
import type {PgCommandQueue} from "../../services/mesh-controller/pg-command-queue.js";

// Replaces InMemoryEnforcer in production. stage/commit/rollback are
// SafeApplyService's fleet-wide staged-policy bookkeeping — not yet bound to
// any node-facing delivery mechanism, so that part stays in-memory, same as
// InMemoryEnforcer, and is not a regression. isolateNode/restoreNode is the
// path ThreatResponseService and SOC emergency lockdown actually call to cut
// a specific node off — with InMemoryEnforcer that only flipped an in-memory
// flag with zero effect on any real node. This persists "QUARANTINE"/
// "RESTORE" — the command types ProductionAgent.execute actually implements
// (agents/shared/production-agent.ts: PlatformAdapter.isolate/restore, no
// secret material involved) — to the same durable command queue the REST
// endpoint-agent heartbeat drains, so the node is actually isolated.
export class PgPolicyEnforcer implements PolicyEnforcer {
  private staged=new Map<string,NetworkPolicy[]>();
  constructor(private queue:PgCommandQueue){}

  async stage(commitId:string,policies:NetworkPolicy[]):Promise<void>{this.staged.set(commitId,policies);}
  async commit(commitId:string):Promise<void>{this.staged.delete(commitId);}
  async rollback(commitId:string):Promise<void>{this.staged.delete(commitId);}

  async isolateNode(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"QUARANTINE",{reason:"policy enforcement point"},200);
  }
  async restoreNode(nodeId:string):Promise<void>{
    await this.queue.enqueue(nodeId,"RESTORE",{},200);
  }
}
