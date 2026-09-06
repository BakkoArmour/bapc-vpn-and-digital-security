import test from "node:test";
import assert from "node:assert/strict";
import {SafeApplyService} from "../../../src/application/safe-apply.js";
import {RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus} from "../../../src/infrastructure/adapters.js";
import type {NetworkPolicy} from "../../../src/domain/types.js";
import type {NodeRolloutRecord} from "../../../src/ports/infrastructure.js";

// SafeApplyService's success criterion used to be ONLY the control plane's
// own database health (PgControlPlaneProbe) — a staged policy could be
// reported COMMITTED even if every node it targeted failed to apply it, as
// long as Postgres itself stayed up. These tests exercise SafeApplyService's
// own polling/threshold/timeout logic directly (fully fake PolicyEnforcer/
// RolloutStore, no Postgres involved — pg-rollout-store.test.ts covers the
// real SQL) to pin down exactly when it now commits vs. rolls back.

const policy:NetworkPolicy={
  id:"p1",name:"deny-legacy-port",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_APP"],
  protocols:["TCP"],destinationPorts:[8080],action:"DENY",requiredRoles:[],requiresJit:false,
  priority:10,version:1,active:true
};

class FakeEnforcer {
  staged:Array<{commitId:string;policies:NetworkPolicy[]}>=[];
  committed:string[]=[];
  rolledBack:string[]=[];
  constructor(private targetedNodeIds:string[]){}
  async stage(commitId:string,policies:NetworkPolicy[]){this.staged.push({commitId,policies});return {targetedNodeIds:this.targetedNodeIds};}
  async commit(commitId:string){this.committed.push(commitId);}
  async rollback(commitId:string){this.rolledBack.push(commitId);}
  async isolateNode(){} async restoreNode(){}
}

// A RolloutStore whose per-node status can change between refresh() calls —
// `advanceAfter` calls become terminal, simulating a node's real heartbeat/
// acknowledgement arriving some polls after the command was enqueued.
class FakeRolloutStore {
  private rows=new Map<string,NodeRolloutRecord>();
  private refreshCalls=0;
  constructor(private schedule:Array<{nodeId:string;afterRefreshes:number;status:"SUCCEEDED"|"FAILED"}>){}
  async start(_commitId:string,nodeIds:string[]){
    for(const nodeId of nodeIds)this.rows.set(nodeId,{nodeId,status:"PENDING",details:{}});
  }
  async refresh(){
    this.refreshCalls++;
    for(const entry of this.schedule){
      if(this.refreshCalls>=entry.afterRefreshes){
        const row=this.rows.get(entry.nodeId);
        if(row&&row.status==="PENDING")row.status=entry.status;
      }
    }
    return this.summary();
  }
  async finalizeTimeouts(){
    for(const row of this.rows.values())if(row.status==="PENDING")row.status="TIMED_OUT";
  }
  async markRolledBack(){for(const row of this.rows.values())row.status="ROLLED_BACK";}
  async summary(){return [...this.rows.values()];}
}

const build=(targetedNodeIds:string[],rollout:FakeRolloutStore,opts:{probe?:()=>Promise<boolean>;threshold?:number;pollIntervalMs?:number}={})=>{
  const enforcer=new FakeEnforcer(targetedNodeIds);
  const service=new SafeApplyService(
    enforcer as any,{verifyControlPlane:opts.probe??(async()=>true)},new MemoryBus(),
    new RandomIds(),new SystemClock(),rollout as any,opts.threshold??0,opts.pollIntervalMs??10
  );
  return {service,enforcer};
};

test("commits as soon as every targeted node reports SUCCEEDED, without waiting out the full timeout",async()=>{
  const rollout=new FakeRolloutStore([
    {nodeId:"n1",afterRefreshes:1,status:"SUCCEEDED"},
    {nodeId:"n2",afterRefreshes:2,status:"SUCCEEDED"}
  ]);
  const {service,enforcer}=build(["n1","n2"],rollout);
  const start=Date.now();
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"COMMITTED");
  assert.deepEqual(enforcer.committed,enforcer.staged.map(s=>s.commitId));
  assert.equal(enforcer.rolledBack.length,0);
  // Resolved via early exit (both nodes terminal after a couple of fast
  // 10ms polls), not by waiting out the 5-second window.
  assert.ok(Date.now()-start<2_000);
});

test("rolls back as soon as a targeted node explicitly reports FAILED (fail-fast, default threshold 0)",async()=>{
  const rollout=new FakeRolloutStore([{nodeId:"n1",afterRefreshes:1,status:"FAILED"}]);
  const {service,enforcer}=build(["n1","n2"],rollout);
  const start=Date.now();
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"ROLLED_BACK");
  assert.match((result as any).reason,/1\/2 targeted node\(s\) failed/);
  assert.deepEqual(enforcer.rolledBack,enforcer.staged.map(s=>s.commitId));
  assert.ok(Date.now()-start<2_000);
});

test("rolls back when nodes never acknowledge within the timeout window (genuine timeout)",async()=>{
  const rollout=new FakeRolloutStore([]); // nothing ever transitions out of PENDING
  const {service,enforcer}=build(["n1"],rollout,{pollIntervalMs:200});
  const result=await service.apply([policy],5_000); // 5s is the enforced minimum window
  assert.equal(result.status,"ROLLED_BACK");
  assert.match((result as any).reason,/1\/1 targeted node\(s\) failed/);
  assert.equal(enforcer.rolledBack.length,1);
});

test("a non-zero nodeFailureThreshold tolerates a minority of failures",async()=>{
  const rollout=new FakeRolloutStore([
    {nodeId:"n1",afterRefreshes:1,status:"FAILED"},
    {nodeId:"n2",afterRefreshes:1,status:"SUCCEEDED"},
    {nodeId:"n3",afterRefreshes:1,status:"SUCCEEDED"}
  ]);
  const {service,enforcer}=build(["n1","n2","n3"],rollout,{threshold:0.5});
  const result=await service.apply([policy],5_000);
  // 1/3 failed = 0.33, at or under the 0.5 threshold -> still commits.
  assert.equal(result.status,"COMMITTED");
  assert.equal(enforcer.committed.length,1);
});

test("an unhealthy control-plane probe still rolls back immediately, before any node is even checked",async()=>{
  const rollout=new FakeRolloutStore([{nodeId:"n1",afterRefreshes:1,status:"SUCCEEDED"}]);
  const {service,enforcer}=build(["n1"],rollout,{probe:async()=>false});
  const start=Date.now();
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"ROLLED_BACK");
  assert.match((result as any).reason,/control plane database unreachable/);
  assert.equal(enforcer.rolledBack.length,1);
  assert.ok(Date.now()-start<2_000);
});

// No mesh nodes at all (an empty/demo environment) falls back to exactly the
// old DB-health-only behavior — there is nothing to verify per-node, and
// that must not itself count as "0 targeted, 0 succeeded -> fail".
test("commits immediately on a healthy probe when there are no targeted nodes to verify",async()=>{
  const rollout=new FakeRolloutStore([]);
  const {service,enforcer}=build([],rollout);
  const start=Date.now();
  const result=await service.apply([policy],5_000);
  assert.equal(result.status,"COMMITTED");
  assert.equal(enforcer.committed.length,1);
  assert.ok(Date.now()-start<1_000);
});

test("rejects a timeout window outside 5-300 seconds without staging anything",async()=>{
  const rollout=new FakeRolloutStore([]);
  const {service,enforcer}=build(["n1"],rollout);
  await assert.rejects(()=>service.apply([policy],1_000),/between 5 and 300 seconds/);
  assert.equal(enforcer.staged.length,0);
});
