import test from "node:test";
import assert from "node:assert/strict";
import {SocService} from "../../../src/application/soc.js";
import {MemoryStore, SystemClock} from "../../../src/infrastructure/memory.js";
import type {Device, MeshNode} from "../../../src/domain/types.js";

// SocService.snapshot() had no test at all, and DeviceRepository.list()
// (now listAll()) collided with NodeRepository's own list() on the same
// repo class — in production (PgRepositories) this meant `this.devices
// .list()` silently read mesh_node rows instead of devices. MeshNode has no
// .revoked/.compromised field, so revokedDevices/compromisedDevices on
// GET /api/v1/soc/snapshot were always 0 no matter how many devices
// actually were. This proves the counts are now real.

const device=(overrides:Partial<Device>):Device=>({
  id:overrides.id!,hostname:"h",hardwareId:`hw-${overrides.id}`,platform:"linux",osVersion:"1",
  compromised:false,revoked:false,
  posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:new Date()},
  createdAt:new Date(),updatedAt:new Date(),...overrides
});
const node=(overrides:Partial<MeshNode>):MeshNode=>({
  id:overrides.id!,deviceId:overrides.id!,wireGuardPublicKey:`pk-${overrides.id}`,
  internalIpv4:"10.144.0.2",internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",
  zone:"ZONE_PROD_APP",active:true,...overrides
});

test("snapshot reports real revoked/compromised device counts, not always zero",async()=>{
  const store=new MemoryStore();
  await store.save(device({id:"d1"}));
  await store.save(device({id:"d2",compromised:true}));
  await store.save(device({id:"d3",revoked:true}));
  await store.save(node({id:"d1"}));
  await store.save(node({id:"d2"}));
  await store.save(node({id:"d3",active:false}));

  const soc=new SocService(store,store,store,store,store,new SystemClock());
  const snapshot=await soc.snapshot();

  assert.equal(snapshot.counts.devices,3);
  assert.equal(snapshot.counts.compromisedDevices,1);
  assert.equal(snapshot.counts.revokedDevices,1);
  assert.equal(snapshot.counts.nodes,3);
  assert.equal(snapshot.counts.activeNodes,2);
});
