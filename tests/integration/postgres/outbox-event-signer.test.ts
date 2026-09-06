import test from "node:test";
import assert from "node:assert/strict";
import {OutboxEventSigner} from "../../../src/infrastructure/outbox-event-signer.js";

// EVENT_SIGNING_SECRET was loaded and enforced at production strength with
// nothing that ever signed anything with it — this is the real HMAC-SHA256
// signing/verification logic maintenance-worker.ts now uses for every
// outbound event_outbox delivery.

test("OutboxEventSigner.verify accepts a signature it produced itself",()=>{
  const signer=new OutboxEventSigner("a".repeat(32));
  const signature=signer.sign("security.policy.committed",{commitId:"c1"});
  assert.equal(signer.verify("security.policy.committed",{commitId:"c1"},signature),true);
});

test("OutboxEventSigner.verify rejects a tampered event payload",()=>{
  const signer=new OutboxEventSigner("a".repeat(32));
  const signature=signer.sign("security.policy.committed",{commitId:"c1"});
  assert.equal(signer.verify("security.policy.committed",{commitId:"c2"},signature),false);
});

test("OutboxEventSigner.verify rejects a signature produced with a different secret",()=>{
  const signature=new OutboxEventSigner("a".repeat(32)).sign("topic",{x:1});
  assert.equal(new OutboxEventSigner("b".repeat(32)).verify("topic",{x:1},signature),false);
});

test("OutboxEventSigner.verify fails closed on a malformed (non-hex) signature instead of throwing",()=>{
  const signer=new OutboxEventSigner("a".repeat(32));
  assert.equal(signer.verify("topic",{x:1},"not-hex-!!"),false);
});
