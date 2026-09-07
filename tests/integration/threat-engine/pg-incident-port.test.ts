import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {PgIncidentPort} from "../../../services/threat-engine/pg-incident-port.js";
import {MemoryStore, RandomIds, SystemClock} from "../../../src/infrastructure/memory.js";
import {Postgres} from "../../../src/infrastructure/postgres/client.js";

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

// incidents.status/closed_at had no write path at all before this — every
// incident opened by ThreatEngine.evaluate stayed OPEN/closed_at=NULL
// forever, with no way for an operator to ever resolve one.
class FakeDbWithRows {
  queries:Array<{text:string;values:unknown[]}>=[];
  rows:any[];
  constructor(rows:any[]){this.rows=rows;}
  async query(text:string,values:unknown[]=[]){this.queries.push({text,values});return {rows:this.rows};}
}

// Found live against real Postgres, not by any mocked test: a stale/
// mistyped nodeId on a threat signal (from a caller other than
// ThreatEngine's own trusted heartbeat path — see /api/v1/threats/signal)
// violated incidents.primary_node_id's foreign key and crashed the whole
// signal-ingestion request with an opaque 500.
class FakeDbFkViolationOnce {
  queries:Array<{text:string;values:unknown[]}>=[];
  private calls=0;
  async query(text:string,values:unknown[]=[]){
    this.queries.push({text,values});
    this.calls++;
    if(this.calls===1){const e:any=new Error("insert or update violates foreign key constraint");e.code="23503";throw e;}
    return {rows:[]};
  }
}

test("open falls back to an unattributed incident when the node doesn't actually exist",async()=>{
  const db=new FakeDbFkViolationOnce();
  const store=new MemoryStore();
  const port=new PgIncidentPort(db,store,new RandomIds(),new SystemClock());
  await port.open({id:"inc-1",nodeId:"stale-node",severity:"CRITICAL",score:75,signals:[]});
  assert.equal(db.queries.length,2);
  assert.match(db.queries[1]!.text,/primary_node_id.*VALUES\(\$1,\$2,\$3,'OPEN',NULL,\$4\)/s);
  const fallbackMetadata=db.queries[1]!.values[3] as any;
  assert.equal(fallbackMetadata.unresolvedNodeId,"stale-node");
});

test("open re-throws a non-foreign-key error instead of masking it",async()=>{
  const db={query:async()=>{throw new Error("connection terminated")}};
  const port=new PgIncidentPort(db,new MemoryStore(),new RandomIds(),new SystemClock());
  await assert.rejects(()=>port.open({id:"inc-1",nodeId:"n1",severity:"CRITICAL",score:75,signals:[]}),/connection terminated/);
});

test("close resolves every OPEN incident for a node and logs a resolution event",async()=>{
  const db=new FakeDbWithRows([{incident_id:"inc-1"},{incident_id:"inc-2"}]);
  const store=new MemoryStore();
  const port=new PgIncidentPort(db,store,new RandomIds(),new SystemClock());
  const count=await port.close("n1","security-analyst-1");
  assert.equal(count,2);
  assert.match(db.queries[0]!.text,/UPDATE bapc_security_core\.incidents SET status='RESOLVED'/);
  assert.deepEqual(db.queries[0]!.values.slice(0,1),["n1"]);
  assert.equal(store.events.length,1);
  assert.equal(store.events[0]!.type,"INCIDENT_RESOLVED");
});

test("close is a no-op with no event logged when there was nothing OPEN to resolve",async()=>{
  const db=new FakeDbWithRows([]);
  const store=new MemoryStore();
  const port=new PgIncidentPort(db,store,new RandomIds(),new SystemClock());
  const count=await port.close("n1","security-analyst-1");
  assert.equal(count,0);
  assert.equal(store.events.length,0);
});

// Every test above mocks db.query — none of them actually parse this SQL.
// The close() query mixes a uuid column and a jsonb->>text extraction in
// one OR'd WHERE clause against the same parameter; a live database is the
// only thing that can confirm Postgres accepts that without a type error
// (exactly the class of bug nodesOverdueForRotation had). This proves the
// full round trip: an incident opened via open()'s unattributed-node
// fallback (primary_node_id=NULL, nodeId only in metadata) is still
// findable and resolvable by close(nodeId).
const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: close resolves an incident opened via the unattributed-node fallback",{skip:!liveDatabaseUrl},async()=>{
  const db=new Postgres(liveDatabaseUrl!);
  const staleNodeId=randomUUID();
  const incidentId=randomUUID();
  try{
    const store=new MemoryStore();
    const port=new PgIncidentPort(db,store,new RandomIds(),new SystemClock());
    // staleNodeId is never enrolled — this must hit the FK-violation fallback.
    await port.open({id:incidentId,nodeId:staleNodeId,severity:"CRITICAL",score:75,signals:[]});

    const count=await port.close(staleNodeId,"security-analyst-1");
    assert.equal(count,1);
  }finally{
    await db.query(`DELETE FROM bapc_security_core.incidents WHERE incident_id=$1`,[incidentId]);
    await db.close();
  }
});
