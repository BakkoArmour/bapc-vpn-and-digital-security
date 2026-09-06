import test from "node:test";
import assert from "node:assert/strict";
import {AuditService} from "../../../src/application/audit.js";
import {MemoryStore, Sha256, SystemClock} from "../../../src/infrastructure/memory.js";

// AuditService.verify()'s core tamper-detection guarantee had no dedicated
// unit test at all — it's only ever exercised indirectly through the real
// production-server.ts routes and live Docker verification in this
// session's other work. Ported from the legacy tests/core.test.ts ahead of
// that file's retirement (see AuditRepository.chain()'s own comment for the
// real collision bug this exact guarantee was found to be broken by before
// this session's earlier fix).

test("audit chain detects no mutation",async()=>{
  const store=new MemoryStore(),service=new AuditService(store,new Sha256(),new SystemClock());
  await service.record("owner","LOCKDOWN","ecosystem",{reason:"test"});
  await service.record("system","RESTORE","ecosystem",{});
  assert.equal(await service.verify(),true);
});

test("audit chain detects a tampered record",async()=>{
  const store=new MemoryStore(),service=new AuditService(store,new Sha256(),new SystemClock());
  await service.record("owner","LOCKDOWN","ecosystem",{reason:"test"});
  await service.record("system","RESTORE","ecosystem",{});
  store.audits[0]!.payload={reason:"tampered"};
  assert.equal(await service.verify(),false);
});
