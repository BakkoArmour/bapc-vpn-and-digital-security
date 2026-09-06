import test from "node:test";
import assert from "node:assert/strict";
import {ThreatEngine} from "../../../services/threat-engine/engine.js";
import {ThreatCorrelator} from "../../../services/threat-engine/correlator.js";
import {InMemoryThreatSignalStore} from "../../../services/threat-engine/threat-signal-store.js";

const buildEngine=(actions:string[],closed?:Array<{nodeId:string;closedBy:string}>)=>new ThreatEngine({
  reauthenticate:async()=>{actions.push("reauth");},
  terminateJit:async()=>{actions.push("jit");},
  isolate:async()=>{actions.push("isolate");},
  revokeNodeCertificates:async()=>{actions.push("revoke");},
  rotateMeshIdentity:async()=>{actions.push("rotate");},
  restore:async()=>{actions.push("restore");}
},{open:async()=>{},event:async()=>{},close:async(nodeId,closedBy)=>{closed?.push({nodeId,closedBy});return closed?.length??0;}});

test("five weak repeated-failed-auth signals correlate into a CRITICAL evaluation",async()=>{
  const actions:string[]=[];
  const correlator=new ThreatCorrelator(buildEngine(actions));
  let last;
  for(let i=0;i<5;i++){
    last=await correlator.ingest({
      nodeId:"n1",kind:"failed_auth",confidence:1,weight:15,at:new Date(),metadata:{}
    });
  }
  // 5 x weight 15 = score 75 -> CRITICAL, even though any single one alone (15) would be INFO.
  assert.equal(last!.severity,"CRITICAL");
  assert.ok(actions.includes("isolate"));
});

test("signals outside the correlation window do not accumulate",async()=>{
  const actions:string[]=[];
  const correlator=new ThreatCorrelator(buildEngine(actions),1_000);
  const old=new Date(Date.now()-5_000);
  await correlator.ingest({nodeId:"n1",kind:"failed_auth",confidence:1,weight:60,at:old,metadata:{}});
  const result=await correlator.ingest({nodeId:"n1",kind:"failed_auth",confidence:1,weight:10,at:new Date(),metadata:{}});
  // the stale 60-weight signal fell out of the window, so only the fresh 10 remains
  assert.equal(result.score,10);
});

test("dismiss clears the window and records the dismissal",async()=>{
  const dismissed:Array<{nodeId:string;dismissedBy:string;signalCount:number}>=[];
  const closed:Array<{nodeId:string;closedBy:string}>=[];
  const correlator=new ThreatCorrelator(buildEngine([],closed),300_000,{
    async record(nodeId,dismissedBy,signalCount){dismissed.push({nodeId,dismissedBy,signalCount});}
  });
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:20,at:new Date(),metadata:{}});
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:20,at:new Date(),metadata:{}});
  assert.equal(await correlator.activeSignalCount("n1"),2);
  const outcome=await correlator.dismiss("n1","security-analyst-1");
  assert.equal(outcome.clearedSignals,2);
  assert.equal(await correlator.activeSignalCount("n1"),0);
  assert.deepEqual(dismissed,[{nodeId:"n1",dismissedBy:"security-analyst-1",signalCount:2}]);
});

// incidents.status/closed_at had no write path at all before this — dismiss
// cleared the signal window but the incidents ThreatEngine.evaluate had
// already opened for this node stayed OPEN forever.
test("dismiss also resolves any open incidents ThreatEngine opened for that node",async()=>{
  const closed:Array<{nodeId:string;closedBy:string}>=[];
  const correlator=new ThreatCorrelator(buildEngine([],closed));
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:20,at:new Date(),metadata:{}});
  await correlator.dismiss("n1","security-analyst-1");
  assert.deepEqual(closed,[{nodeId:"n1",closedBy:"security-analyst-1"}]);
});

test("different nodes have independent correlation windows",async()=>{
  const correlator=new ThreatCorrelator(buildEngine([]));
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:50,at:new Date(),metadata:{}});
  const resultN2=await correlator.ingest({nodeId:"n2",kind:"scan",confidence:1,weight:5,at:new Date(),metadata:{}});
  assert.equal(resultN2.score,5);
});

// The whole point of accepting a ThreatSignalStore (threat-signal-store.ts)
// instead of keeping a private Map: the sliding window's state lives in the
// store, not the correlator instance. A brand new ThreatCorrelator built
// against the SAME store (the real-world equivalent of a control-plane
// process restarting, with PgThreatSignalStore's Postgres table surviving
// the restart) still sees signals accumulated before it existed.
test("a signal ingested by one ThreatCorrelator instance still contributes to a later evaluation from a fresh instance sharing the same store",async()=>{
  const store=new InMemoryThreatSignalStore();
  const beforeRestart=new ThreatCorrelator(buildEngine([]),300_000,undefined,store);
  await beforeRestart.ingest({nodeId:"n1",kind:"failed_auth",confidence:1,weight:60,at:new Date(),metadata:{}});

  const actionsAfterRestart:string[]=[];
  const afterRestart=new ThreatCorrelator(buildEngine(actionsAfterRestart),300_000,undefined,store);
  const result=await afterRestart.ingest({nodeId:"n1",kind:"failed_auth",confidence:1,weight:20,at:new Date(),metadata:{}});
  // 60 (pre-restart) + 20 (post-restart) = 80 -> CRITICAL. If the restart had
  // erased the window, this would score only 20 and stay INFO.
  assert.equal(result.score,80);
  assert.equal(result.severity,"CRITICAL");
  assert.ok(actionsAfterRestart.includes("isolate"));
});
