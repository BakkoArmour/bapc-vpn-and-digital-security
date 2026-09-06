import test from "node:test";
import assert from "node:assert/strict";
import {upsertIssuerRow} from "../../../services/trust-core/trust-anchor.js";

// certificate_issuers.is_active (db/002_operational_tables.sql) existed with
// no read path at all — nothing ever checked it, so an operator had no real
// way to hard-stop issuance from a compromised or retired anchor.

class FakeDb {
  queries:Array<{text:string;values:unknown[]}>=[];
  constructor(private rows:any[]){}
  async query(text:string,values:unknown[]=[]){this.queries.push({text,values});return {rows:this.rows};}
}

test("upsertIssuerRow returns the issuer id when the row is active",async()=>{
  const db=new FakeDb([{issuer_id:"issuer-1"}]);
  const id=await upsertIssuerRow(db as any,"CERT-PEM","key-ref");
  assert.equal(id,"issuer-1");
  assert.match(db.queries[0]!.text,/ON CONFLICT \(name\) DO UPDATE/);
  assert.match(db.queries[0]!.text,/WHERE certificate_issuers\.is_active/);
});

test("upsertIssuerRow fails closed when the existing issuer row has been deactivated",async()=>{
  // ON CONFLICT ... WHERE <false> DO UPDATE is a no-op for that row: no
  // rows come back from RETURNING, exactly as Postgres would behave against
  // a real is_active=false row.
  const db=new FakeDb([]);
  await assert.rejects(
    ()=>upsertIssuerRow(db as any,"CERT-PEM","key-ref"),
    /deactivated/
  );
});
