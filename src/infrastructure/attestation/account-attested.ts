import {createHmac, timingSafeEqual} from "node:crypto";
import type {AttestationVerifier} from "../../ports/infrastructure.js";
import {canonicalJson} from "../canonical-json.js";

// "Account-attested" enrollment, for devices that can't produce hardware
// evidence this control plane verifies: iPhone, Android and Mac using the
// stock WireGuard app, which has no TPM attestation of its own.
//
// What vouches for such a device instead is the customer portal itself:
// it only ever produces this proof after confirming a signed-in bapc.app
// account that BAPC Billing says has paid, and within that account's device
// limit (src/application/customer-devices.ts). The proof is an HMAC under a
// key only the portal process holds, so it can't be forged from outside,
// and it is bound to the exact hardware id and identity key being enrolled.
//
// This is deliberately NOT selectable as ATTESTATION_PROVIDER. The public
// join route (POST /api/v1/devices/join) keeps verifying real windows-tpm
// evidence; only the portal's own EnrollmentService instance uses this.
export class AccountAttestedVerifier implements AttestationVerifier {
  constructor(private secret:string){
    if(secret.length<32)throw new Error("account attestation secret must be at least 32 characters");
  }

  private mac(hardwareId:string,identityPublicKeyPem:string):Buffer{
    return createHmac("sha256",this.secret)
      .update(canonicalJson({purpose:"bapc-account-attested-enrollment",hardwareId,identityPublicKeyPem}))
      .digest();
  }

  proof(hardwareId:string,identityPublicKeyPem:string):Uint8Array{
    return new Uint8Array(this.mac(hardwareId,identityPublicKeyPem));
  }

  async verify(hardwareId:string,quote:Uint8Array,identityPublicKeyPem?:string):Promise<boolean>{
    if(!identityPublicKeyPem)return false;
    const expected=this.mac(hardwareId,identityPublicKeyPem);
    const given=Buffer.from(quote);
    return given.length===expected.length&&timingSafeEqual(given,expected);
  }
}
