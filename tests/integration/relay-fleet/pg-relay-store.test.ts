import test from "node:test";
import assert from "node:assert/strict";
import {PgRelayStore} from "../../../services/relay-fleet/pg-relay-store.js";

test("PgRelayStore issues the expected SQL for insert, get and remove",async()=>{
  const queries:Array<{text:string;values:unknown[]}>=[];
  const store=new PgRelayStore({
    query:async(text:string,values:unknown[]=[])=>{
      queries.push({text,values});
      if(text.includes("SELECT"))return {rows:[{relay_id:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",is_available:true,instance_id:"i-abc"}]};
      return {rows:[]};
    }
  });
  await store.insert("r1","us-east-1","203.0.113.10:51900","i-abc");
  const row=await store.get("r1");
  await store.remove("r1");

  assert.match(queries[0]!.text,/INSERT INTO bapc_security_core\.relays/);
  assert.deepEqual(queries[0]!.values,["r1","us-east-1","203.0.113.10:51900","i-abc"]);
  assert.match(queries[1]!.text,/SELECT .* FROM bapc_security_core\.relays/);
  assert.deepEqual(row,{relayId:"r1",region:"us-east-1",endpoint:"203.0.113.10:51900",isAvailable:true,instanceId:"i-abc"});
  assert.match(queries[2]!.text,/DELETE FROM bapc_security_core\.relays/);
});

test("PgRelayStore.get returns null for an unknown relay",async()=>{
  const store=new PgRelayStore({query:async()=>({rows:[]})});
  assert.equal(await store.get("missing"),null);
});
