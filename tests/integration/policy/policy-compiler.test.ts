import test from "node:test";
import assert from "node:assert/strict";
import {PolicyCompiler} from "../../../src/application/policy-compiler.js";
import type {NetworkPolicy} from "../../../src/domain/types.js";

// PolicyCompiler.linux()/windows()/apple()'s platform-specific plan output
// (ebpfMapEntries, wfpFilters, networkExtensionRules) had no dedicated test
// — command-sinks.test.ts only exercises PgPolicyEnforcer.stage()'s
// port/zone validation path (which uses PolicyCompiler internally), never
// asserting on what linux()/windows() actually produce from a compiled IR.
// Ported from the legacy tests/expanded.test.ts ahead of that file's
// retirement.

const policy:NetworkPolicy={
  id:"p1",name:"deny-dev-prod",sourceZones:["ZONE_DEV"],destinationZones:["ZONE_PROD_DATA"],
  protocols:["ANY"],destinationPorts:[],action:"DENY",requiredRoles:[],requiresJit:false,
  priority:10,version:1,active:true
};

test("PolicyCompiler.compile produces a validated, checksummed IR",()=>{
  const ir=new PolicyCompiler().compile([policy]);
  assert.equal(ir.rules.length,1);
  assert.equal(ir.rules[0]!.action,"DENY");
  assert.match(ir.checksum,/^[0-9a-f]{64}$/);
});

test("PolicyCompiler.linux produces one eBPF map entry per rule and an nftables fallback",()=>{
  const compiler=new PolicyCompiler();
  const plan=compiler.linux(compiler.compile([policy]));
  assert.equal(plan.ebpfMapEntries.length,1);
  assert.equal(plan.ebpfMapEntries[0]!.value,"DENY");
  assert.equal(plan.nftablesFallback.length,1);
  assert.match(plan.nftablesFallback[0]!,/^deny /);
});

test("PolicyCompiler.windows maps DENY to a BLOCK WFP filter",()=>{
  const compiler=new PolicyCompiler();
  const plan=compiler.windows(compiler.compile([policy]));
  assert.equal(plan.wfpFilters[0]!.action,"BLOCK");
  assert.equal(plan.wfpFilters[0]!.layer,"ALE_AUTH_CONNECT_V4_V6");
});

test("PolicyCompiler.windows maps ALLOW to a PERMIT WFP filter",()=>{
  const compiler=new PolicyCompiler();
  const plan=compiler.windows(compiler.compile([{...policy,action:"ALLOW"}]));
  assert.equal(plan.wfpFilters[0]!.action,"PERMIT");
});

test("PolicyCompiler.apple maps DENY to a drop NetworkExtension rule",()=>{
  const compiler=new PolicyCompiler();
  const plan=compiler.apple(compiler.compile([policy]));
  assert.equal(plan.networkExtensionRules[0]!.action,"drop");
  assert.deepEqual(plan.networkExtensionRules[0]!.matchNetworks,["ZONE_PROD_DATA"]);
});
