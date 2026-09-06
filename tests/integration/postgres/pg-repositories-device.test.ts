import test from "node:test";
import assert from "node:assert/strict";
import {PgRepositories} from "../../../src/infrastructure/postgres/repositories.js";
import type {Device} from "../../../src/domain/types.js";

// devices.last_posture_at/agent_version/quarantine_reason existed with no
// write/read path in PgRepositories at all before this — HeartbeatService
// .accept and ThreatResponseService.handle/restore need these persisted,
// not silently dropped on every save().

const testDevice=(overrides:Partial<Device> = {}):Device=>({
  id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux",osVersion:"1",
  compromised:false,revoked:false,
  posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
  createdAt:new Date(),updatedAt:new Date(),
  ...overrides
});

test("PgRepositories.save(Device) writes last_posture_at, agent_version and quarantine_reason",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const db={query:async(text:string,values:unknown[]=[])=>{queries.push({text,values});return {rows:[],rowCount:0};}};
  const repo=new PgRepositories(db as any);
  const postureAt=new Date("2026-01-01T00:00:00.000Z");
  await repo.save(testDevice({lastPostureAt:postureAt,agentVersion:"1.4.0",quarantineReason:"repeated failed auth"}));
  assert.match(queries[0]!.text,/last_posture_at/);
  assert.match(queries[0]!.text,/agent_version/);
  assert.match(queries[0]!.text,/quarantine_reason/);
  assert.equal(queries[0]!.values.includes(postureAt),true);
  assert.equal(queries[0]!.values.includes("1.4.0"),true);
  assert.equal(queries[0]!.values.includes("repeated failed auth"),true);
});

test("PgRepositories.save(Device) writes null for a brand-new device with none of these set yet",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const db={query:async(text:string,values:unknown[]=[])=>{queries.push({text,values});return {rows:[],rowCount:0};}};
  const repo=new PgRepositories(db as any);
  await repo.save(testDevice());
  const values=queries[0]!.values;
  assert.equal(values[values.length-1],null);
  assert.equal(values[values.length-2],null);
  assert.equal(values[values.length-3],null);
});

test("PgRepositories.findByHardwareId maps last_posture_at, agent_version and quarantine_reason back onto the real Device",async()=>{
  const db={
    query:async()=>({rows:[{
      device_id:"d1",hostname:"h",hardware_uuid:"hw1",platform:"linux",os_version:"1",
      is_compromised:true,is_revoked:false,
      posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
      created_at:new Date(),updated_at:new Date(),
      last_posture_at:new Date("2026-01-01T00:00:00.000Z"),agent_version:"1.4.0",quarantine_reason:"repeated failed auth"
    }],rowCount:1})
  };
  const repo=new PgRepositories(db as any);
  const device=await repo.findByHardwareId("hw1");
  assert.equal(device!.agentVersion,"1.4.0");
  assert.equal(device!.quarantineReason,"repeated failed auth");
  assert.equal(device!.lastPostureAt?.toISOString(),"2026-01-01T00:00:00.000Z");
});
