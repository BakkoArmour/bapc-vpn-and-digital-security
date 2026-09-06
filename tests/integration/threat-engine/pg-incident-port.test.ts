import test from "node:test";
import assert from "node:assert/strict";
import {PgIncidentPort} from "../../../services/threat-engine/pg-incident-port.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";

// incidents (db/002_operational_tables.sql) had no write path at all before
// this — ThreatEngine.evaluate's open() had nowhere real to persist to.

class FakeDb {
  queries:Array<{text:string;values:unknown[]}>=[];
  async query(text:string,values:unknown[]=[]){this.queries.push({text,values});return {rows:[]};}
}

test("open inserts a real row into incidents",async()=>{
  const db=new FakeDb();
  const port=new PgIncidentPort(db,new MemoryStore(),new RandomIds(),new SystemClock());
  await port.open({id:"inc-1",nodeId:"n1",severity:"CRITICAL",score:75,signals:[{kind:"failed_auth"}]});
  assert.equal(db.queries.length,1);
  assert.match(db.queries[0]!.text,/INSERT INTO bapc_security_core\.incidents/);
  assert.deepEqual(db.queries[0]!.values[0],"inc-1");
  assert.deepEqual(db.queries[0]!.values[3],"n1");
});

test("open passes null for primary_node_id when no node is attributed",async()=>{
  const db=new FakeDb();
  const port=new PgIncidentPort(db,new MemoryStore(),new RandomIds(),new SystemClock());
  await port.open({id:"inc-2",severity:"WARN",score:40,signals:[]});
  assert.equal(db.queries[0]!.values[3],null);
});

test("event appends a real SecurityEvent through EventRepository",async()=>{
  const store=new MemoryStore();
  const port=new PgIncidentPort(new FakeDb(),store,new RandomIds(),new SystemClock());
  await port.event({severity:"CRITICAL",type:"THREAT_EVALUATED",description:"threat score 75",metadata:{score:75}});
  assert.equal(store.events.length,1);
  assert.equal(store.events[0]!.type,"THREAT_EVALUATED");
  assert.equal(store.events[0]!.engine,"threat-correlator");
});
