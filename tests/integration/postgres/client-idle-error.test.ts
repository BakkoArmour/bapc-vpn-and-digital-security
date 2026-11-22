import test from "node:test";
import assert from "node:assert/strict";
import {Postgres} from "../../../src/infrastructure/postgres/client.js";

// 22 Nov 2026: a database restart ended the pool's idle connections, the pool emitted "error" with no listener, and
// every BAPC VPN service exited ("uncaught_exception"). A lost idle connection must be logged, never fatal.
test("a lost idle connection is logged and does not throw",async()=>{
  const db=new Postgres("postgresql://nobody@127.0.0.1:1/none");
  const logged:string[]=[];
  const original=console.error;
  console.error=(line:string)=>{logged.push(line);};
  try{
    assert.doesNotThrow(()=>db.pool.emit("error",new Error("terminating connection due to administrator command")));
  }finally{console.error=original;}
  assert.equal(logged.length,1);
  assert.deepEqual(JSON.parse(logged[0]!),{event:"postgres.idle_connection_lost",error:"terminating connection due to administrator command"});
  await db.pool.end();
});
