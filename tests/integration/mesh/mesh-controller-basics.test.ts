import test from "node:test";
import assert from "node:assert/strict";
import {AddressAllocator, MeshController} from "../../../services/mesh-controller/controller.js";

// AddressAllocator.next() and MeshController.quarantine() had no dedicated
// unit test — quarantine specifically is only ever exercised indirectly
// through PgPolicyEnforcer/ThreatResponseService, never called on
// MeshController itself. Ported from the legacy tests/addendum.test.ts
// ahead of that file's retirement.

test("AddressAllocator.next skips used addresses",async()=>{
  const a=new AddressAllocator({
    usedIpv4:async()=>new Set(["10.144.10.3"]),
    usedIpv6:async()=>new Set(["fd14:4b41:5043::2"])
  });
  const lease=await a.next();
  assert.ok(lease.ipv4.startsWith("10.144."));
  assert.notEqual(lease.ipv4,"10.144.10.3");
  assert.ok(lease.ipv6.startsWith("fd14:4b41:5043::"));
  assert.notEqual(lease.ipv6,"fd14:4b41:5043::2");
});

test("MeshController.quarantine severs the node via the sink",async()=>{
  let severed="";
  const c=new MeshController({configure:async()=>{},sever:async id=>{severed=id;}});
  await c.quarantine("node-1");
  assert.equal(severed,"node-1");
});
