import test from "node:test";
import assert from "node:assert/strict";
import {SignedEventClient} from "../../../integrations/signed-event-client.js";
import {EcosystemIntegrationService, type SignedEcosystemEvent} from "../../../src/application/integrations.js";
import {MemoryBus} from "../../../src/infrastructure/adapters.js";

// integrations/signed-event-client.ts (the OUTBOUND publisher this repo would
// use to call out to BAPC Diagnostics/Headquarters/Cloud-Deployment/
// Integration) and src/application/integrations.ts's EcosystemIntegrationService
// (the INBOUND verifier those sibling apps' events pass through here) were
// written in two separate build documents. This proves they actually agree
// on the wire format rather than just trusting both look right independently.

test("an event signed by SignedEventClient is accepted by EcosystemIntegrationService",async()=>{
  const secret="shared-hmac-secret-between-bapc-services";
  let sent:SignedEcosystemEvent|undefined;
  const client=new SignedEventClient("diagnostics",secret,async event=>{sent=event as SignedEcosystemEvent;});
  await client.publish("threat.confirmed",{nodeId:"n1",severity:"CRITICAL"});

  assert.ok(sent);
  const integrations=new EcosystemIntegrationService({
    diagnostics:secret,headquarters:"x",["cloud-deployment"]:"x",integration:"x"
  },new MemoryBus());
  const result=await integrations.accept(sent!);
  assert.equal(result.accepted,true);
});

test("a tampered payload is rejected even with the original signature",async()=>{
  const secret="shared-hmac-secret-between-bapc-services";
  let sent:SignedEcosystemEvent|undefined;
  const client=new SignedEventClient("headquarters",secret,async event=>{sent=event as SignedEcosystemEvent;});
  await client.publish("owner.alert",{message:"original"});

  const tampered={...sent!,payload:{message:"tampered"}};
  const integrations=new EcosystemIntegrationService({
    diagnostics:"x",headquarters:secret,["cloud-deployment"]:"x",integration:"x"
  },new MemoryBus());
  await assert.rejects(()=>integrations.accept(tampered),/invalid ecosystem signature/);
});

test("an event outside the replay window is rejected",async()=>{
  const secret="shared-hmac-secret-between-bapc-services";
  let sent:SignedEcosystemEvent|undefined;
  const client=new SignedEventClient("integration",secret,async event=>{sent=event as SignedEcosystemEvent;});
  await client.publish("webhook.received",{id:"abc"});

  const integrations=new EcosystemIntegrationService({
    diagnostics:"x",headquarters:"x",["cloud-deployment"]:"x",integration:secret
  },new MemoryBus());
  const farFuture=new Date(Date.now()+10*60_000);
  await assert.rejects(()=>integrations.accept(sent!,farFuture),/replay window/);
});
