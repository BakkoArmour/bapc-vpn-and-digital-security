import {createHmac, timingSafeEqual} from "node:crypto";
import type {AccessDecision} from "../domain/types.js";
import type {DecisionSigner} from "../ports/infrastructure.js";

// Real HMAC-SHA256 signature over an AccessDecision's stable fields. Policy
// Enforcement Points (an endpoint agent's local firewall, an API gateway)
// need to verify a decision came from this Policy Decision Point and hasn't
// been tampered with in transit — using the same secret they already hold
// to authenticate to the control API means no additional secret
// distribution is needed just to verify decisions.
export class HmacDecisionSigner implements DecisionSigner {
  constructor(private secret:string){}
  private body(d:AccessDecision){
    return JSON.stringify({
      decisionId:d.decisionId,allowed:d.allowed,action:d.action,reason:d.reason,
      policyId:d.policyId??null,expiresAt:d.expiresAt.toISOString()
    });
  }
  async sign(d:AccessDecision){
    return createHmac("sha256",this.secret).update(this.body(d)).digest("hex");
  }
  async verify(d:AccessDecision,signature:string){
    const expected=Buffer.from(await this.sign(d),"hex");
    const actual=Buffer.from(signature,"hex");
    return expected.length===actual.length&&timingSafeEqual(expected,actual);
  }
}
