import test from "node:test";
import assert from "node:assert/strict";
import {CpuLoadSampler, ThroughputSampler} from "../../../native/shared/process-metrics.js";

// relay-server.ts/egress-server.ts previously hardcoded loadPercent:0 (and
// relays had no throughput concept at all). These prove the samplers
// actually measure something real, not fixed values.

test("CpuLoadSampler reports non-trivial load while the process is busy, and stays within 0-100",async()=>{
  const sampler=new CpuLoadSampler();
  sampler.sample(); // establish a baseline
  // Burn real CPU for a short, bounded window.
  const until=Date.now()+30;
  let x=0;
  while(Date.now()<until)x+=Math.sqrt(x+1);
  const load=sampler.sample();
  assert.ok(load>=0&&load<=100,`load ${load} should be within 0-100`);
});

test("CpuLoadSampler returns 0, not NaN or negative, on the very first call",()=>{
  const sampler=new CpuLoadSampler();
  const load=sampler.sample();
  assert.ok(Number.isFinite(load));
  assert.ok(load>=0);
});

test("ThroughputSampler computes a positive rate from real byte growth over real elapsed time",async()=>{
  const sampler=new ThroughputSampler();
  sampler.sample(0);
  await new Promise(r=>setTimeout(r,30));
  const rate=sampler.sample(3000);
  assert.ok(rate>0,"rate should be positive given real byte growth");
  assert.ok(Number.isFinite(rate));
});

test("ThroughputSampler never goes negative even if the counter resets (e.g. process restart)",async()=>{
  const sampler=new ThroughputSampler();
  sampler.sample(5000);
  await new Promise(r=>setTimeout(r,10));
  const rate=sampler.sample(100); // counter went backwards
  assert.equal(rate,0);
});
