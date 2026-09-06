import test from "node:test";
import assert from "node:assert/strict";
import {ThreatEngine} from "../../../services/threat-engine/engine.js";
import {ThreatCorrelator} from "../../../services/threat-engine/correlator.js";

const buildEngine=(actions:string[])=>new ThreatEngine({
  reauthenticate:async()=>{actions.push("reauth");},
  terminateJit:async()=>{actions.push("jit");},
  isolate:async()=>{actions.push("isolate");},
  revokeNodeCertificates:async()=>{actions.push("revoke");},
  rotateMeshIdentity:async()=>{actions.push("rotate");},
  restore:async()=>{actions.push("restore");}
},{open:async()=>{},event:async()=>{}});

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
  const correlator=new ThreatCorrelator(buildEngine([]),300_000,{
    async record(nodeId,dismissedBy,signalCount){dismissed.push({nodeId,dismissedBy,signalCount});}
  });
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:20,at:new Date(),metadata:{}});
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:20,at:new Date(),metadata:{}});
  assert.equal(correlator.activeSignalCount("n1"),2);
  const outcome=await correlator.dismiss("n1","security-analyst-1");
  assert.equal(outcome.clearedSignals,2);
  assert.equal(correlator.activeSignalCount("n1"),0);
  assert.deepEqual(dismissed,[{nodeId:"n1",dismissedBy:"security-analyst-1",signalCount:2}]);
});

test("different nodes have independent correlation windows",async()=>{
  const correlator=new ThreatCorrelator(buildEngine([]));
  await correlator.ingest({nodeId:"n1",kind:"scan",confidence:1,weight:50,at:new Date(),metadata:{}});
  const resultN2=await correlator.ingest({nodeId:"n2",kind:"scan",confidence:1,weight:5,at:new Date(),metadata:{}});
  assert.equal(resultN2.score,5);
});
