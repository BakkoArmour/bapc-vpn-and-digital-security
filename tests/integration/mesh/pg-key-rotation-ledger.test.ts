import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {PgKeyRotationLedger} from "../../../services/mesh-controller/pg-key-rotation-ledger.js";
import {Postgres} from "../../../src/infrastructure/postgres/client.js";

// KEY_ROTATION_DAYS (config.ts) had no consumer at all — nothing ever read
// a node's rotation history to decide whether it was overdue. This is that
// query's own SQL-shape test; src/application/key-rotation-scheduler.ts
// tests the decision logic built on top of it.

test("PgKeyRotationLedger.nodesOverdueForRotation queries the max rotated_at per node against the configured window",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const now=new Date();
  const ledger=new PgKeyRotationLedger({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{node_id:"n1"},{node_id:"n2"}]};
    }
  });
  const overdue=await ledger.nodesOverdueForRotation(30,now);
  assert.match(queries[0]!.text,/MAX\(rotated_at\)/);
  assert.match(queries[0]!.text,/make_interval\(days=>\$1\)/);
  assert.deepEqual(queries[0]!.values,[30,now]);
  assert.deepEqual(overdue,["n1","n2"]);
});

test("PgKeyRotationLedger.nodesOverdueForRotation returns an empty list when nothing is overdue",async()=>{
  const ledger=new PgKeyRotationLedger({query:async()=>({rows:[]})});
  assert.deepEqual(await ledger.nodesOverdueForRotation(30,new Date()),[]);
});

// Every test above mocks db.query and never actually parses this SQL — a
// real Postgres instance previously rejected it outright ("operator does
// not exist: timestamp with time zone < interval") because $2 (a bare Date
// parameter subtracted against make_interval(...)) was type-ambiguous. Only
// a live database catches that; caught via full Docker Compose
// verification, not by the mocked tests above.
const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: nodesOverdueForRotation actually executes against real Postgres",{skip:!liveDatabaseUrl},async()=>{
  const {PgRepositories}=await import("../../../src/infrastructure/postgres/repositories.js");
  const db=new Postgres(liveDatabaseUrl!);
  const deviceId=randomUUID(),nodeId=randomUUID();
  try{
    const repo=new PgRepositories(db);
    const now=new Date();
    await repo.save({
      id:deviceId,hostname:"h",hardwareId:`hw-${deviceId}`,platform:"linux" as const,osVersion:"1",
      compromised:false,revoked:false,
      posture:{osCurrent:true,diskEncrypted:true,secureBoot:true,firewallEnabled:true,agentHealthy:true,bannedProcessFound:false,assessedAt:now},
      createdAt:now,updatedAt:now
    });
    await repo.save({
      id:nodeId,deviceId,wireGuardPublicKey:`pk-${nodeId}`,internalIpv4:"10.99.0.1",internalIpv6:"::1",
      listenPort:51820,nodeType:"SERVER" as const,zone:"ZONE_PROD_APP" as const,active:true
    });
    const oldRotation=new Date(Date.now()-60*86_400_000);
    await db.query(
      `INSERT INTO bapc_security_core.key_rotations(node_id,epoch,new_public_key,rotated_at) VALUES($1,1,'old-key',$2)`,
      [nodeId,oldRotation]
    );

    const ledger=new PgKeyRotationLedger(db);
    const overdue=await ledger.nodesOverdueForRotation(30,new Date());
    assert.ok(overdue.includes(nodeId));

    const notOverdue=await ledger.nodesOverdueForRotation(90,new Date());
    assert.equal(notOverdue.includes(nodeId),false);
  }finally{
    await db.query(`DELETE FROM bapc_security_core.mesh_nodes WHERE node_id=$1`,[nodeId]);
    await db.query(`DELETE FROM bapc_security_core.devices WHERE device_id=$1`,[deviceId]);
    await db.close();
  }
});
