import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {MigrationRunner, type MigrationFile, type PgLike, type PgQueryable} from "../../../src/infrastructure/postgres/migrate.js";

// A minimal in-memory PgLike fake so the runner's ordering/checksum/lock
// bookkeeping is verified without a live Postgres server.
class FakePg implements PgLike {
  executed:string[]=[];
  tables=new Map<string,{name:string;checksum:string}>();
  schemaReady=false;
  async query<T>(text:string, values:unknown[]=[]):Promise<{rows:T[]}>{
    this.executed.push(text.trim().split("\n")[0]!);
    if(text.startsWith("CREATE TABLE IF NOT EXISTS public.schema_migrations")){
      this.schemaReady=true; return {rows:[] as T[]};
    }
    if(text.startsWith("SELECT name,checksum FROM public.schema_migrations")
      || text.startsWith("SELECT name,checksum,applied_at FROM public.schema_migrations")){
      return {rows:[...this.tables.values()].map(t=>({...t,applied_at:new Date()})) as T[]};
    }
    if(text.startsWith("INSERT INTO public.schema_migrations")){
      const [name,checksum]=values as [string,string];
      this.tables.set(name,{name,checksum});
      return {rows:[] as T[]};
    }
    if(text.startsWith("SELECT pg_advisory_xact_lock")) return {rows:[] as T[]};
    return {rows:[] as T[]}; // any other statement is treated as the migration body itself
  }
  async transaction<T>(work:(client:PgQueryable)=>Promise<T>):Promise<T>{
    return work(this);
  }
}

const fixture=(name:string, sql:string):MigrationFile => ({
  name, sql, checksum: createHash("sha256").update(sql).digest("hex")
});

test("applies migrations in order and records them",async()=>{
  const pg=new FakePg();
  const runner=new MigrationRunner(pg);
  const migrations=[fixture("001_a.sql","CREATE TABLE a();"),fixture("002_b.sql","CREATE TABLE b();")];
  const result=await runner.apply(migrations);
  assert.deepEqual(result.applied,["001_a.sql","002_b.sql"]);
  assert.deepEqual(result.skipped,[]);
  assert.ok(pg.schemaReady);
});

test("skips already-applied migrations with matching checksum",async()=>{
  const pg=new FakePg();
  const runner=new MigrationRunner(pg);
  const migrations=[fixture("001_a.sql","CREATE TABLE a();")];
  await runner.apply(migrations);
  const second=await runner.apply(migrations);
  assert.deepEqual(second.applied,[]);
  assert.deepEqual(second.skipped,["001_a.sql"]);
});

test("rejects a migration whose applied content has drifted",async()=>{
  const pg=new FakePg();
  const runner=new MigrationRunner(pg);
  await runner.apply([fixture("001_a.sql","CREATE TABLE a();")]);
  await assert.rejects(
    ()=>runner.apply([fixture("001_a.sql","DROP TABLE a;")]),
    /checksum mismatch/
  );
});

test("status reports pending and applied migrations",async()=>{
  const pg=new FakePg();
  const runner=new MigrationRunner(pg);
  const migrations=[fixture("001_a.sql","CREATE TABLE a();"),fixture("002_b.sql","CREATE TABLE b();")];
  await runner.apply([migrations[0]!]);
  const status=await runner.status(migrations);
  assert.equal(status[0]!.applied,true);
  assert.equal(status[1]!.applied,false);
});

// Full end-to-end migration + repository round trip against a REAL Postgres.
// Skipped unless DATABASE_URL points at a reachable database, e.g.:
//   docker compose -f deploy/docker-compose.yml up -d db
//   DATABASE_URL=postgres://bapc:bapc@localhost:5432/bapc_security_core npm test
const liveDatabaseUrl=process.env.DATABASE_URL;
test("live: full schema migrates cleanly against real Postgres",{skip:!liveDatabaseUrl},async()=>{
  const {Postgres}=await import("../../../src/infrastructure/postgres/client.js");
  const {loadMigrations}=await import("../../../src/infrastructure/postgres/migrate.js");
  const db=new Postgres(liveDatabaseUrl!);
  try{
    const {fileURLToPath}=await import("node:url");
    const runner=new MigrationRunner(db);
    const migrations=loadMigrations(fileURLToPath(new URL("../../../../db",import.meta.url)));
    const first=await runner.apply(migrations);
    assert.ok(first.applied.length>0 || first.skipped.length>0);
    const second=await runner.apply(migrations);
    assert.deepEqual(second.applied,[]);
  }finally{
    await db.close();
  }
});

// Regression coverage for a real bug found by actually running this against
// Postgres in Docker: purge_expired_control_plane_rows() (006/008) used
// unqualified table names relying on the MIGRATION session's `SET
// search_path` — which doesn't travel with the function definition, so any
// later caller with its own default search_path (exactly how the app's own
// connection pool calls it) got "relation ... does not exist". Explicitly
// resetting search_path here (rather than relying on whatever a pooled
// connection happens to have inherited) makes this test actually exercise
// that failure mode instead of possibly passing by accident of connection
// reuse.
test("live: retention/partition functions resolve their tables regardless of the caller's search_path",{skip:!liveDatabaseUrl},async()=>{
  const {Postgres}=await import("../../../src/infrastructure/postgres/client.js");
  const {loadMigrations}=await import("../../../src/infrastructure/postgres/migrate.js");
  const {fileURLToPath}=await import("node:url");
  const db=new Postgres(liveDatabaseUrl!);
  try{
    const runner=new MigrationRunner(db);
    await runner.apply(loadMigrations(fileURLToPath(new URL("../../../../db",import.meta.url))));
    await db.transaction(async client=>{
      await client.query("SET search_path TO public");
      await client.query("SELECT bapc_security_core.ensure_month_partition(CURRENT_DATE)");
      await client.query("SELECT bapc_security_core.drop_expired_event_partitions(120)");
      const purged=await client.query("SELECT * FROM bapc_security_core.purge_expired_control_plane_rows()");
      assert.equal(purged.rows.length,1);
      assert.ok("idempotency_deleted" in purged.rows[0]!);
    });
  }finally{
    await db.close();
  }
});
