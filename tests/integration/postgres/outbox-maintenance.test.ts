import test from "node:test";
import assert from "node:assert/strict";
import {OutboxDispatcher} from "../../../src/infrastructure/postgres/outbox.js";
import {RetentionService} from "../../../src/infrastructure/postgres/maintenance.js";
import type {Postgres} from "../../../src/infrastructure/postgres/client.js";

// Fakes satisfying Postgres's public shape structurally (no private members
// on that class), so OutboxDispatcher/RetentionService — both written
// against the concrete Postgres class rather than a narrow interface — can
// still be unit tested without a live database.
const fakeTransactionalDb=(rows:any[]):{db:Postgres;queries:string[]}=>{
  const queries:string[]=[];
  const client={
    query:async(text:string,_values?:unknown[])=>{
      queries.push(text.trim().split("\n")[0]!);
      if(text.startsWith("SELECT outbox_id"))return {rows,rowCount:rows.length};
      return {rows:[],rowCount:0};
    }
  };
  const db={
    pool:{} as any,
    query:client.query,
    transaction:async(work:(c:typeof client)=>Promise<any>)=>work(client),
    health:async()=>true,
    close:async()=>{}
  } as unknown as Postgres;
  return {db,queries};
};

test("OutboxDispatcher.flush delivers each unpublished row and marks it published",async()=>{
  const rows=[
    {outbox_id:"o1",topic:"security.jit.requested",payload:{a:1}},
    {outbox_id:"o2",topic:"security.node.restored",payload:{b:2}}
  ];
  const {db,queries}=fakeTransactionalDb(rows);
  const delivered:Array<{topic:string;event:unknown}>=[];
  const dispatcher=new OutboxDispatcher(db,async(topic,event)=>{delivered.push({topic,event});});
  const count=await dispatcher.flush();
  assert.equal(count,2);
  assert.deepEqual(delivered,[
    {topic:"security.jit.requested",event:{a:1}},
    {topic:"security.node.restored",event:{b:2}}
  ]);
  assert.ok(queries.some(q=>q.includes("UPDATE bapc_security_core.event_outbox")));
});

test("OutboxDispatcher.flush records a per-row failure without blocking other rows",async()=>{
  const rows=[
    {outbox_id:"o1",topic:"will-fail",payload:{}},
    {outbox_id:"o2",topic:"will-succeed",payload:{}}
  ];
  const {db}=fakeTransactionalDb(rows);
  const delivered:string[]=[];
  const dispatcher=new OutboxDispatcher(db,async(topic)=>{
    if(topic==="will-fail")throw new Error("downstream unavailable");
    delivered.push(topic);
  });
  const count=await dispatcher.flush();
  assert.equal(count,2); // both rows were claimed by the SELECT, even though one failed to deliver
  assert.deepEqual(delivered,["will-succeed"]);
});

test("OutboxDispatcher.flush's SELECT and UPDATEs run inside one transaction (concurrency-safety for SKIP LOCKED)",async()=>{
  let transactionCalls=0;
  const client={query:async(text:string)=>{
    if(text.startsWith("SELECT outbox_id"))return {rows:[{outbox_id:"o1",topic:"t",payload:{}}],rowCount:1};
    return {rows:[],rowCount:0};
  }};
  const db={
    pool:{} as any,query:client.query,
    transaction:async(work:any)=>{transactionCalls++;return work(client);},
    health:async()=>true,close:async()=>{}
  } as unknown as Postgres;
  const dispatcher=new OutboxDispatcher(db,async()=>{});
  await dispatcher.flush();
  assert.equal(transactionCalls,1);
});

test("RetentionService issues the expected SQL for each maintenance operation",async()=>{
  const queries:string[]=[];
  const db={
    pool:{} as any,
    query:async(text:string,_values?:unknown[])=>{
      queries.push(text.trim().split("\n")[0]!.trim());
      if(text.includes("ensure_month_partition"))return {rows:[{ensure_month_partition:"security_events_2026_09"}]};
      if(text.includes("drop_expired_event_partitions"))return {rows:[{drop_expired_event_partitions:"security_events_2024_01"}]};
      if(text.includes("purge_expired_control_plane_rows"))return {rows:[{idempotency_deleted:"3",nonces_deleted:"1",outbox_deleted:"0"}]};
      return {rows:[]};
    },
    transaction:async(work:any)=>work({query:async()=>({rows:[]})}),
    health:async()=>true,close:async()=>{}
  } as unknown as Postgres;
  const retention=new RetentionService(db);

  const created=await retention.ensureUpcomingPartitions(1);
  assert.deepEqual(created,["security_events_2026_09","security_events_2026_09"]);

  const dropped=await retention.dropExpiredPartitions(13);
  assert.deepEqual(dropped,["security_events_2024_01"]);

  const purged=await retention.purgeExpiredRows();
  assert.deepEqual(purged,{idempotencyDeleted:3,noncesDeleted:1,outboxDeleted:0});
});
