import test from "node:test";
import assert from "node:assert/strict";
import {KeyRotationSchedulerService} from "../../../src/application/key-rotation-scheduler.js";

test("KeyRotationSchedulerService enqueues ROTATE_IDENTITY_REQUIRED for every overdue node",async()=>{
  const enqueued:Array<{nodeId:string;type:string;payload:unknown;priority:number|undefined}>=[];
  const scheduler=new KeyRotationSchedulerService(
    {nodesOverdueForRotation:async()=>["n1","n2"]},
    {enqueue:async(nodeId,type,payload,priority)=>{enqueued.push({nodeId,type,payload,priority});}},
    30
  );
  const result=await scheduler.run();
  assert.equal(result.checked,2);
  assert.deepEqual(enqueued.map(e=>e.nodeId),["n1","n2"]);
  assert.ok(enqueued.every(e=>e.type==="ROTATE_IDENTITY_REQUIRED"));
});

test("KeyRotationSchedulerService enqueues nothing when no node is overdue",async()=>{
  let enqueueCalls=0;
  const scheduler=new KeyRotationSchedulerService(
    {nodesOverdueForRotation:async()=>[]},
    {enqueue:async()=>{enqueueCalls++;}},
    30
  );
  const result=await scheduler.run();
  assert.equal(result.checked,0);
  assert.equal(enqueueCalls,0);
});

test("KeyRotationSchedulerService passes its configured maxAgeDays through to the source",async()=>{
  let seenMaxAgeDays:number|undefined;
  const scheduler=new KeyRotationSchedulerService(
    {nodesOverdueForRotation:async(maxAgeDays)=>{seenMaxAgeDays=maxAgeDays;return [];}},
    {enqueue:async()=>{}},
    45
  );
  await scheduler.run();
  assert.equal(seenMaxAgeDays,45);
});
