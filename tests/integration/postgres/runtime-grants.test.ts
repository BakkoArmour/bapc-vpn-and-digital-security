import test from "node:test";
import assert from "node:assert/strict";
import {runtimeGrantStatements} from "../../../src/infrastructure/postgres/runtime-grants.js";

// Under BAPC Cheisgos the services sign in as a runtime role: rows only, never schema changes, and later tables
// (monthly partitions) covered through default privileges.
test("runtime role gets rows-only access to the app schema, now and for later tables",()=>{
  const s=runtimeGrantStatements("bapc_vpn_rw");
  assert.ok(s.includes('GRANT USAGE ON SCHEMA "bapc_security_core" TO "bapc_vpn_rw"'));
  assert.ok(s.includes('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "bapc_security_core" TO "bapc_vpn_rw"'));
  assert.ok(s.some((x)=>x.startsWith('ALTER DEFAULT PRIVILEGES IN SCHEMA "bapc_security_core" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES')));
  assert.ok(!s.some((x)=>/\b(CREATE|ALL PRIVILEGES|TRUNCATE|REFERENCES|TRIGGER)\b/.test(x)));
});

test("refuses role names that are not plain identifiers",()=>{
  for(const bad of ["", "Bapc", "rw; DROP TABLE x", "a\"b", "x".repeat(64)]) assert.throws(()=>runtimeGrantStatements(bad),/plain role name/);
});
