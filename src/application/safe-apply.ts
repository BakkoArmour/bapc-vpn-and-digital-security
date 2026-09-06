import { ValidationError } from "../domain/errors.js";
import type { NetworkPolicy } from "../domain/types.js";
import type { Clock, ConnectivityProbe, EventBus, IdGenerator, PolicyEnforcer, RolloutStore, NodeRolloutRecord } from "../ports/infrastructure.js";
import { InMemoryRolloutStore } from "../infrastructure/in-memory-rollout-store.js";

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));

// SafeApplyService's success criterion used to be ONLY
// ConnectivityProbe.verifyControlPlane() — in production, the control
// plane's own database health. A staged policy could be reported COMMITTED
// even if every targeted node failed to apply it, or never received it at
// all, as long as Postgres itself stayed reachable. `rollout` (a
// RolloutStore — see ports/infrastructure.ts and pg-rollout-store.ts) closes
// that gap: every node PolicyEnforcer.stage actually targeted is tracked
// individually against its real command_acknowledgements, and a rollout only
// commits when enough of them report real success — not merely because the
// database that queued their commands happens to be up.
export class SafeApplyService {
  constructor(
    private enforce:PolicyEnforcer,private probe:ConnectivityProbe,private bus:EventBus,
    private ids:IdGenerator,private clock:Clock,
    private rollout:RolloutStore=new InMemoryRolloutStore(),
    // Fraction (0-1) of targeted nodes allowed to end up FAILED/TIMED_OUT
    // before the rollout is rolled back. Defaults to 0 — the strictest,
    // safest default: any node that explicitly fails or never checks in
    // within the window triggers a fleet-wide rollback. An operator running
    // a large, occasionally-flaky fleet can loosen this via
    // SAFE_APPLY_NODE_FAILURE_THRESHOLD (see config.ts).
    private nodeFailureThreshold=0,
    // How often to re-check node status while waiting out the timeout
    // window. Independent of timeoutMs (which has its own 5s-300s floor/
    // ceiling below) so tests can inject a tiny interval and resolve as
    // soon as a fake store reports a terminal status, without waiting out
    // a real multi-second timeout for the common case.
    private pollIntervalMs=1_000
  ){}

  async apply(policies:NetworkPolicy[],timeoutMs=60_000,initiatedBy?:string){
    if(timeoutMs<5_000||timeoutMs>300_000)throw new ValidationError("rollback window must be between 5 and 300 seconds");
    const commitId=this.ids.next();
    const {targetedNodeIds}=await this.enforce.stage(commitId,policies,initiatedBy);
    await this.rollout.start(commitId,targetedNodeIds);
    await this.bus.publish("security.policy.staged",{commitId,at:this.clock.now(),timeoutMs,targetedNodeIds});

    try{
      const rollbackReason=await this.waitForOutcome(commitId,targetedNodeIds,timeoutMs);
      if(rollbackReason){
        await this.rollout.markRolledBack(commitId);
        await this.enforce.rollback(commitId);
        await this.bus.publish("security.policy.rolled_back",{commitId,reason:rollbackReason});
        return {commitId,status:"ROLLED_BACK" as const,reason:rollbackReason};
      }
      await this.enforce.commit(commitId);
      await this.bus.publish("security.policy.committed",{commitId});
      return {commitId,status:"COMMITTED" as const};
    }catch(error){
      await this.rollout.markRolledBack(commitId);
      await this.enforce.rollback(commitId);
      throw error;
    }
  }

  // Polls until either (a) the DB probe fails, (b) too many targeted nodes
  // have a terminal FAILED status already (fail fast — no reason to wait out
  // the rest of the window for an explicit failure), (c) every targeted node
  // has reached a terminal status (exit early — no reason to wait out the
  // rest of the window once everyone has answered), or (d) the timeout
  // elapses, at which point any still-PENDING node is finalized as
  // TIMED_OUT and counted against the threshold like a failure. Returns a
  // reason string if the rollout should be rolled back, or undefined if it
  // should commit.
  private async waitForOutcome(commitId:string,targetedNodeIds:string[],timeoutMs:number):Promise<string|undefined>{
    const deadline=Date.now()+timeoutMs;
    while(Date.now()<deadline){
      // Raced against the remaining window, not awaited directly: the
      // original implementation raced verifyControlPlane() against the
      // whole timeout so a probe that hangs (rather than rejecting) still
      // resolves this to a rollback instead of blocking forever — that
      // safety property must survive being split into a polling loop.
      const remaining=deadline-Date.now();
      const probeHealthy=await Promise.race([
        this.probe.verifyControlPlane(),
        sleep(remaining).then(()=>false)
      ]);
      if(!probeHealthy)return "control plane database unreachable";
      const statuses=targetedNodeIds.length>0?await this.rollout.refresh(commitId):[];
      const failureReason=this.failureReason(statuses,targetedNodeIds.length);
      if(failureReason)return failureReason;
      const allTerminal=statuses.every(s=>s.status!=="PENDING");
      if(targetedNodeIds.length===0||allTerminal)return undefined;
      await sleep(Math.min(this.pollIntervalMs,Math.max(0,deadline-Date.now())));
    }
    await this.rollout.finalizeTimeouts(commitId);
    const finalStatuses=await this.rollout.summary(commitId);
    return this.failureReason(finalStatuses,targetedNodeIds.length,true);
  }

  private failureReason(statuses:NodeRolloutRecord[],targetCount:number,includeTimedOut=false):string|undefined{
    if(targetCount===0)return undefined;
    const bad=statuses.filter(s=>s.status==="FAILED"||(includeTimedOut&&s.status==="TIMED_OUT")).length;
    if(bad/targetCount>this.nodeFailureThreshold){
      return `${bad}/${targetCount} targeted node(s) failed to apply the policy (threshold ${this.nodeFailureThreshold})`;
    }
    return undefined;
  }
}
