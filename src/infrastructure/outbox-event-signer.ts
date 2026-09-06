import {createHmac, timingSafeEqual} from "node:crypto";

// EVENT_SIGNING_SECRET (config.ts) was loaded and even enforced at
// production-strength (>=32 chars) with nothing anywhere that ever actually
// signed anything with it — every outbound event_outbox delivery
// (OutboxDispatcher, src/infrastructure/postgres/outbox.ts) went out
// unsigned. Mirrors HmacDecisionSigner's exact pattern: a real HMAC-SHA256
// signature a receiving sibling app (BAPC Diagnostics/Headquarters/etc.)
// can verify came from this control plane and wasn't tampered with in
// transit, once a real receiver exists to send it to — see
// src/runtime/maintenance-worker.ts's own comment on why the delivery sink
// itself is still a structured log, not a live HTTP call.
export class OutboxEventSigner {
  constructor(private secret:string){}
  sign(topic:string,event:unknown):string{
    return createHmac("sha256",this.secret).update(topic).update(JSON.stringify(event)).digest("hex");
  }
  verify(topic:string,event:unknown,signature:string):boolean{
    const expected=Buffer.from(this.sign(topic,event),"hex");
    let actual:Buffer;
    try{actual=Buffer.from(signature,"hex");}catch{return false;}
    return expected.length===actual.length&&timingSafeEqual(expected,actual);
  }
}
