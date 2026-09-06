import test from "node:test";
import assert from "node:assert/strict";
import {HmacBearerGuard} from "../../../src/api/rest/guard.js";

// HmacBearerGuard.mint() (scripts/mint-token.mjs's real signing path) had no
// dedicated test at all — router.test.ts only ever verifies tokens it
// crafts by hand with createHmac, never mint() itself. Ported from the
// legacy tests/addendum.test.ts ahead of that file's retirement.

test("HmacBearerGuard.mint produces a token verify() accepts",()=>{
  const secret="y".repeat(32);
  const token=HmacBearerGuard.mint({sub:"11111111-1111-1111-1111-111111111111",roles:["security-owner"]},secret);
  const req={headers:{authorization:`Bearer ${token}`}} as any;
  const claims=new HmacBearerGuard(secret).verify(req,["security-owner"]);
  assert.equal(claims.sub,"11111111-1111-1111-1111-111111111111");
  assert.deepEqual(claims.roles,["security-owner"]);
});

test("HmacBearerGuard.mint defaults exp to now+3600s and honors an explicit exp",()=>{
  const secret="y".repeat(32);
  const before=Math.floor(Date.now()/1000);
  const defaulted=HmacBearerGuard.mint({sub:"u1",roles:[]},secret);
  const [encodedDefault]=defaulted.split(".");
  const defaultClaims=JSON.parse(Buffer.from(encodedDefault!,"base64url").toString("utf8"));
  assert.ok(defaultClaims.exp>=before+3600&&defaultClaims.exp<=before+3601);

  const explicit=HmacBearerGuard.mint({sub:"u1",roles:[],exp:before+10},secret);
  const [encodedExplicit]=explicit.split(".");
  const explicitClaims=JSON.parse(Buffer.from(encodedExplicit!,"base64url").toString("utf8"));
  assert.equal(explicitClaims.exp,before+10);
});

test("a token minted with the wrong secret fails verification",()=>{
  const token=HmacBearerGuard.mint({sub:"u1",roles:["security-read"]},"a".repeat(32));
  const req={headers:{authorization:`Bearer ${token}`}} as any;
  assert.throws(()=>new HmacBearerGuard("b".repeat(32)).verify(req,["security-read"]));
});
