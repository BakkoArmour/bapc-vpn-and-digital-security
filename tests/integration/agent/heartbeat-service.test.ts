import test from "node:test";
import assert from "node:assert/strict";
import {HeartbeatService, type Heartbeat} from "../../../src/application/heartbeat.js";
import {MemoryStore, SystemClock} from "../../../src/infrastructure/memory.js";
import {MemoryBus} from "../../../src/infrastructure/adapters.js";
import type {Device, MeshNode} from "../../../src/domain/types.js";

// devices.last_posture_at/agent_version had no write path at all before
// this — HeartbeatService.accept recorded a device's posture but never the
// timestamp it was taken at, nor which agent version reported it.

const goodPosture=()=>({osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()});

const setup=async()=>{
  const store=new MemoryStore();
  const device:Device={id:"d1",hostname:"h",hardwareId:"hw1",platform:"linux",osVersion:"1",
    compromised:false,revoked:false,posture:goodPosture(),createdAt:new Date(),updatedAt:new Date()};
  const node:MeshNode={id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.0.0.1",internalIpv6:"::1",
    listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true};
  await store.save(device);await store.save(node);
  return {store,service:new HeartbeatService(store,store,new MemoryBus(),new SystemClock())};
};

test("HeartbeatService.accept records lastPostureAt and agentVersion on the device",async()=>{
  const {store,service}=await setup();
  const at=new Date();
  const heartbeat:Heartbeat={nodeId:"n1",at,posture:goodPosture(),bytesTransmitted:0,bytesReceived:0,agentVersion:"1.4.0"};
  await service.accept(heartbeat);
  const device=await store.devices.get("d1");
  assert.equal(device?.lastPostureAt?.getTime(),at.getTime());
  assert.equal(device?.agentVersion,"1.4.0");
});

test("HeartbeatService.accept updates lastPostureAt and agentVersion on every subsequent heartbeat",async()=>{
  const {store,service}=await setup();
  await service.accept({nodeId:"n1",at:new Date(Date.now()-1000),posture:goodPosture(),bytesTransmitted:0,bytesReceived:0,agentVersion:"1.4.0"});
  const secondAt=new Date();
  await service.accept({nodeId:"n1",at:secondAt,posture:goodPosture(),bytesTransmitted:0,bytesReceived:0,agentVersion:"1.5.0"});
  const device=await store.devices.get("d1");
  assert.equal(device?.lastPostureAt?.getTime(),secondAt.getTime());
  assert.equal(device?.agentVersion,"1.5.0");
});
