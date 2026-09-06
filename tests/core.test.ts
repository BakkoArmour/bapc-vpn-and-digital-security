import test from "node:test";import assert from "node:assert/strict";
import {AuditService} from "../src/application/audit.js";import {SafeApplyService} from "../src/application/safe-apply.js";import {JitService} from "../src/application/jit.js";import {MemoryStore,RandomIds,Sha256,SystemClock} from "../src/infrastructure/memory.js";import {HealthyProbe,InMemoryEnforcer,MemoryBus} from "../src/infrastructure/adapters.js";
test("audit chain detects no mutation",async()=>{const store=new MemoryStore(),service=new AuditService(store,new Sha256(),new SystemClock());await service.record("owner","LOCKDOWN","ecosystem",{reason:"test"});await service.record("system","RESTORE","ecosystem",{});assert.equal(await service.verify(),true);});
// AuditRepository.list() collided with NodeRepository/DeviceRepository's own
// list() on the same store class — verify() was silently walking an empty
// or wrong array (chain() is the fix) and always returning true regardless
// of tampering. This proves it actually detects a mutated record now.
test("audit chain detects a tampered record",async()=>{const store=new MemoryStore(),service=new AuditService(store,new Sha256(),new SystemClock());await service.record("owner","LOCKDOWN","ecosystem",{reason:"test"});await service.record("system","RESTORE","ecosystem",{});store.audits[0]!.payload={reason:"tampered"};assert.equal(await service.verify(),false);});
test("safe apply commits after a healthy probe",async()=>{const enforcer=new InMemoryEnforcer(),service=new SafeApplyService(enforcer,new HealthyProbe(),new MemoryBus(),new RandomIds(),new SystemClock());const result=await service.apply([],5000);assert.equal(result.status,"COMMITTED");});
test("JIT rejects empty justification",async()=>{const service=new JitService(new MemoryStore(),new RandomIds(),new SystemClock(),new MemoryBus());await assert.rejects(()=>service.request("u","db","ZONE_PROD_DATA",15,"short"));});
