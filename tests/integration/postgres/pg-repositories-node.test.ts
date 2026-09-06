import test from "node:test";
import assert from "node:assert/strict";
import {PgRepositories} from "../../../src/infrastructure/postgres/repositories.js";
import type {MeshNode} from "../../../src/domain/types.js";

// mesh_nodes.region (db/019_mesh_node_region.sql) had no write/read path in
// PgRepositories at all before this — RelayRoutingService/MeshController
// need a real node region to distinguish LOCAL_RELAY from REGIONAL_RELAY
// (see services/mesh-controller/controller.ts).

const testNode=(overrides:Partial<MeshNode> = {}):MeshNode=>({
  id:"n1",deviceId:"d1",wireGuardPublicKey:"pk",internalIpv4:"10.144.0.2",
  internalIpv6:"fd14::2",listenPort:51820,nodeType:"SERVER",zone:"ZONE_PROD_APP",active:true,
  ...overrides
});

test("PgRepositories.save(MeshNode) omits region from the query entirely when the caller doesn't supply one",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const db={query:async(text:string,values:unknown[]=[])=>{queries.push({text,values});return {rows:[],rowCount:0};}};
  const repo=new PgRepositories(db as any);
  await repo.save(testNode());
  assert.doesNotMatch(queries[0]!.text,/region/);
  assert.equal(queries[0]!.values.includes("ZONE_PROD_APP"),true);
});

// Enrollment (src/api/grpc/server.ts) builds a MeshNode with no region at
// all — a later heartbeat re-save must not silently wipe out an operator's
// prior PUT /api/v1/nodes/:id/region assignment back to the schema default.
test("PgRepositories.save(MeshNode) sets region only when the caller explicitly supplies one",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const db={query:async(text:string,values:unknown[]=[])=>{queries.push({text,values});return {rows:[],rowCount:0};}};
  const repo=new PgRepositories(db as any);
  await repo.save(testNode({region:"us-east-1"}));
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.mesh_nodes/);
  assert.match(queries[0]!.text,/region/);
  assert.match(queries[0]!.text,/region=EXCLUDED\.region/);
  assert.equal(queries[0]!.values.includes("us-east-1"),true);
});

test("PgRepositories.findByPublicKey maps region back onto the real MeshNode",async()=>{
  const db={
    query:async()=>({rows:[{
      node_id:"n1",device_id:"d1",public_key:"pk",internal_ipv4:"10.144.0.2",internal_ipv6:"fd14::2",
      listen_port:51820,node_type:"SERVER",zone_assignment:"ZONE_PROD_APP",region:"eu-west-1",
      is_active:true,last_handshake:null
    }],rowCount:1})
  };
  const repo=new PgRepositories(db as any);
  const node=await repo.findByPublicKey("pk");
  assert.equal(node!.region,"eu-west-1");
});
