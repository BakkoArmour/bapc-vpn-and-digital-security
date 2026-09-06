import test from "node:test";
import assert from "node:assert/strict";
import {EgressSelector} from "../../../services/egress/selector.js";

// EgressSelector.select()'s fail-closed behavior on zero candidates had no
// dedicated test — pg-egress-store.test.ts only tests PgEgressStore, and
// relay-egress.test.ts only tests the real socket-level proxy, neither of
// which exercises EgressSelector's own selection/throw logic directly.
// Ported from the legacy tests/addendum.test.ts ahead of that file's
// retirement.

test("EgressSelector.select fails closed (throws) when there are no candidates at all",()=>{
  assert.throws(()=>new EgressSelector().select([],"us-east"),/no healthy egress gateway/);
});

test("EgressSelector.select prefers a gateway in the preferred region over a healthier one elsewhere",()=>{
  const gateway=(overrides:Partial<Parameters<EgressSelector["select"]>[0][number]>={}):Parameters<EgressSelector["select"]>[0][number]=>({
    id:"g",region:"us-east-1",fixedIp:"203.0.113.1",healthy:true,loadPercent:10,
    lastCheck:new Date(),latencyMs:20,activeSessions:5,capacityPercent:10,...overrides
  });
  const selected=new EgressSelector().select([
    gateway({id:"far-but-idle",region:"eu-west-1",loadPercent:0,latencyMs:0,capacityPercent:0}),
    gateway({id:"near",region:"us-east-1",loadPercent:30,latencyMs:40,capacityPercent:20})
  ],"us-east-1");
  assert.equal(selected.id,"near");
});
