import test from "node:test";
import assert from "node:assert/strict";
import {OobServer} from "../../../services/oob-controller/oob-server.js";
import {HttpOobChannel} from "../../../services/oob-controller/http-channel.js";
import {OobController, type RecoveryStore} from "../../../services/oob-controller/controller.js";
import {PgRecoveryStore} from "../../../services/oob-controller/pg-recovery-store.js";

const SECRET="oob-shared-secret-at-least-32-characters-long";

const startOob=async()=>{
  const server=new OobServer(SECRET);
  await server.start(0,"127.0.0.1");
  const port=(server.address() as any).port;
  const channel=new HttpOobChannel(`http://127.0.0.1:${port}`,SECRET);
  return {server,channel};
};

class MemoryRecoveryStore implements RecoveryStore {
  snapshots:any[]=[];
  async save(snapshot:any){this.snapshots.push(snapshot);}
  async lastKnownGood(scope:string){return [...this.snapshots].reverse().find(s=>s.scope===scope&&s.lkg);}
}

test("OobServer rejects requests without the shared secret",async()=>{
  const {server}=await startOob();
  try{
    const port=(server.address() as any).port;
    const res=await fetch(`http://127.0.0.1:${port}/oob/documents/mesh-policy`);
    assert.equal(res.status,401);
  }finally{await server.stop();}
});

test("OobController checkpoint pushes and verifies over the real HTTP channel",async()=>{
  const {server,channel}=await startOob();
  try{
    const store=new MemoryRecoveryStore();
    const controller=new OobController(store,channel);
    const snapshot=await controller.checkpoint("mesh-policy",{rules:["allow prod"]},"operator-1");
    assert.equal(store.snapshots.length,1);
    assert.equal(store.snapshots[0].checksum,snapshot.checksum);
  }finally{await server.stop();}
});

test("OobController rollback restores the last-known-good document",async()=>{
  const {server,channel}=await startOob();
  try{
    const store=new MemoryRecoveryStore();
    const controller=new OobController(store,channel);
    await controller.checkpoint("mesh-policy",{rules:["allow prod"]},"operator-1");
    await controller.checkpoint("mesh-policy",{rules:["allow prod","allow dev"]},"operator-1");

    // Simulate a bad live push that the channel now disagrees with...
    await channel.push("mesh-policy",{rules:["BROKEN"]});
    const result=await controller.rollback("mesh-policy");
    assert.equal(result.restored,store.snapshots.at(-1).id);

    const verified=await channel.verify("mesh-policy",store.snapshots.at(-1).checksum);
    assert.equal(verified,true);
  }finally{await server.stop();}
});

test("OobController rollback fails when the channel is unhealthy",async()=>{
  const store=new MemoryRecoveryStore();
  store.snapshots.push({id:"s1",scope:"mesh-policy",checksum:"abc",document:{},lkg:true});
  const unhealthyChannel={
    async healthy(){return false;},
    async push(){throw new Error("unreachable");},
    async verify(){return false;}
  };
  const controller=new OobController(store,unhealthyChannel);
  await assert.rejects(()=>controller.rollback("mesh-policy"),/OOB channel unavailable/);
});

test("PgRecoveryStore clears the previous last-known-good before inserting the new one",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRecoveryStore({
    query:async(text,values=[])=>{queries.push({text,values});return {rows:[]};}
  });
  await store.save({id:"s2",scope:"mesh-policy",checksum:"c2",document:{},createdBy:"op",lkg:true});
  assert.match(queries[0]!.text,/UPDATE bapc_security_core\.recovery_snapshots/);
  assert.match(queries[1]!.text,/INSERT INTO bapc_security_core\.recovery_snapshots/);
});

// The SOC console's recovery/OOB status panel (Item 3) needs every scope's
// current posture at once — previously the only read path (lastKnownGood)
// required already knowing which scope to ask about.
test("PgRecoveryStore.listLastKnownGood returns every scope's current last-known-good, most recent first",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const at=new Date();
  const store=new PgRecoveryStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{scope:"mesh-policy",snapshot_id:"s1",checksum:"c1",created_by:"op-1",created_at:at.toISOString()}]};
    }
  });
  const all=await store.listLastKnownGood();
  assert.match(queries[0]!.text,/WHERE is_last_known_good=true/);
  assert.match(queries[0]!.text,/ORDER BY created_at DESC/);
  assert.equal(all[0]!.scope,"mesh-policy");
  assert.equal(all[0]!.id,"s1");
  assert.equal(all[0]!.createdBy,"op-1");
});
