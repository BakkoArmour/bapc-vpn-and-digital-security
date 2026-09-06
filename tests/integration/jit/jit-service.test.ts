import test from "node:test";
import assert from "node:assert/strict";
import {JitService} from "../../../src/application/jit.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus} from "../../../src/infrastructure/adapters.js";

// JitService.request()'s justification-length validation had no dedicated
// test — every other JIT-related test constructs a grant object directly
// rather than going through request() itself. Ported from the legacy
// tests/core.test.ts ahead of that file's retirement.

test("JIT rejects empty justification",async()=>{
  const service=new JitService(new MemoryStore(),new RandomIds(),new SystemClock(),new MemoryBus());
  await assert.rejects(()=>service.request("u","db","ZONE_PROD_DATA",15,"short"));
});

test("JIT accepts a meaningful justification and publishes the request",async()=>{
  const bus=new MemoryBus();
  const service=new JitService(new MemoryStore(),new RandomIds(),new SystemClock(),bus);
  const grant=await service.request("u1","prod-db-1","ZONE_PROD_DATA",30,"investigating a production incident");
  assert.equal(grant.userId,"u1");
  assert.equal(grant.terminated,false);
  assert.equal(bus.events.length,1);
  assert.equal(bus.events[0]!.topic,"security.jit.requested");
});
