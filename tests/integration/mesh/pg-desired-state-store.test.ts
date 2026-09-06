import test from "node:test";
import assert from "node:assert/strict";
import {PgDesiredStateStore} from "../../../services/mesh-controller/pg-desired-state-store.js";

// node_desired_state (db/016_node_desired_state.sql) had no repository at
// all before this — RECONCILE's real producer (NodeReconciliationService,
// src/application/node-reconciliation.ts) needs somewhere to read "what
// should this node look like" from.

test("PgDesiredStateStore.get returns null for a node with no desired state configured",async()=>{
  const store=new PgDesiredStateStore({query:async()=>({rows:[]})});
  assert.equal(await store.get("missing"),null);
});

test("PgDesiredStateStore.upsert inserts a new node at revision 1",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgDesiredStateStore({
    query:async(text,values=[])=>{
      queries.push({text,values});
      return {rows:[{node_id:"n1",revision:1,routes:[],dns_servers:["1.1.1.1"],kill_switch_enabled:true,integrity_files:{},updated_at:new Date().toISOString()}]};
    }
  });
  const state=await store.upsert("n1",{routes:[],dnsServers:["1.1.1.1"],killSwitchEnabled:true,integrityFiles:{}},"operator-1");
  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.node_desired_state/);
  assert.match(queries[0]!.text,/ON CONFLICT\(node_id\) DO UPDATE/);
  assert.equal(state.revision,1);
  assert.equal(state.killSwitchEnabled,true);
});

// A re-PUT always bumps the revision, even with identical values — a PUT is
// itself a legitimate reason to re-verify the node actually has them (see
// the store's own comment).
test("PgDesiredStateStore.upsert increments revision on every call, even with unchanged values",async()=>{
  const store=new PgDesiredStateStore({
    query:async()=>({rows:[{node_id:"n1",revision:4,routes:[],dns_servers:[],kill_switch_enabled:false,integrity_files:{},updated_at:new Date().toISOString()}]})
  });
  const state=await store.upsert("n1",{routes:[],dnsServers:[],killSwitchEnabled:false,integrityFiles:{}});
  assert.equal(state.revision,4);
});

test("PgDesiredStateStore.get parses jsonb columns back into real objects",async()=>{
  const routes=[{destination:"10.0.0.0/8",interfaceName:"wg0",metric:100}];
  const store=new PgDesiredStateStore({
    query:async()=>({rows:[{
      node_id:"n1",revision:2,routes:JSON.stringify(routes),dns_servers:JSON.stringify(["9.9.9.9"]),
      kill_switch_enabled:false,integrity_files:JSON.stringify({"/etc/wg0.conf":"abc123"}),updated_at:new Date().toISOString()
    }]})
  });
  const state=await store.get("n1");
  assert.deepEqual(state!.routes,routes);
  assert.deepEqual(state!.dnsServers,["9.9.9.9"]);
  assert.deepEqual(state!.integrityFiles,{"/etc/wg0.conf":"abc123"});
});

test("PgDesiredStateStore.all returns every configured node's desired state",async()=>{
  const store=new PgDesiredStateStore({
    query:async(text)=>{
      assert.doesNotMatch(text,/WHERE/);
      return {rows:[
        {node_id:"n1",revision:1,routes:[],dns_servers:[],kill_switch_enabled:false,integrity_files:{},updated_at:new Date().toISOString()},
        {node_id:"n2",revision:3,routes:[],dns_servers:[],kill_switch_enabled:true,integrity_files:{},updated_at:new Date().toISOString()}
      ]};
    }
  });
  const all=await store.all();
  assert.equal(all.length,2);
  assert.equal(all[1]!.nodeId,"n2");
});
