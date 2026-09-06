import {randomUUID} from "node:crypto";
import {EcosystemIntegrationService, type SignedEcosystemEvent} from "../src/application/integrations.js";
import type {ClearanceVerifier} from "../src/application/threat-response.js";

export interface ClearancePayload {nodeId:string; approvedBy:string; caseId:string;}

// Real signature-verifying clearance check: a "diag-clearance:" token is
// nothing more than a base64url-encoded SignedEcosystemEvent from BAPC
// Diagnostics™ (source:"diagnostics", type:"forensic.clearance") — so
// verifying it reuses EcosystemIntegrationService.accept's existing HMAC
// signature check and replay-window enforcement rather than inventing a
// second crypto scheme. This closes the gap flagged in
// docs/INCIDENT-RESPONSE-RUNBOOK.md: the previous check only confirmed the
// token's string prefix, never its signature.
export class DiagnosticsClearanceVerifier implements ClearanceVerifier {
  constructor(private integrations:EcosystemIntegrationService){}

  async verify(token:string,nodeId:string,now:Date){
    if(!token.startsWith("diag-clearance:"))throw new Error("signed Diagnostics clearance required");
    let event:SignedEcosystemEvent;
    try{
      event=JSON.parse(Buffer.from(token.slice("diag-clearance:".length),"base64url").toString("utf8"));
    }catch{
      throw new Error("malformed Diagnostics clearance token");
    }
    if(event.source!=="diagnostics")throw new Error("clearance must be signed by BAPC Diagnostics");
    if(event.type!=="forensic.clearance")throw new Error("wrong clearance event type");
    await this.integrations.accept(event,now); // verifies signature + replay window; publishes the ecosystem event
    const payload=event.payload as unknown as ClearancePayload;
    if(payload.nodeId!==nodeId)throw new Error("clearance token is not scoped to this node");
    if(!payload.approvedBy||!payload.caseId)throw new Error("clearance token is missing approvedBy/caseId");
    return {approvedBy:payload.approvedBy,caseId:payload.caseId};
  }
}

// Builds a token the way BAPC Diagnostics™ would — used by tests and by
// operator tooling standing in for Diagnostics before that integration
// exists. Requires the same "diagnostics" secret the verifier's
// EcosystemIntegrationService was constructed with.
export const issueClearanceToken=(
  integrations:EcosystemIntegrationService,payload:ClearancePayload,at=new Date()
):string=>{
  const unsigned={source:"diagnostics" as const,type:"forensic.clearance",at:at.toISOString(),nonce:randomUUID(),payload:payload as unknown as Record<string,unknown>};
  const signature=integrations.sign(unsigned);
  return "diag-clearance:"+Buffer.from(JSON.stringify({...unsigned,signature})).toString("base64url");
};
