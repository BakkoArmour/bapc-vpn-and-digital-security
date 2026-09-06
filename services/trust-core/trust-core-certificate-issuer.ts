import type {CertificateIssuer} from "../../src/ports/infrastructure.js";
import {TrustCoreIssuer} from "./issuer.js";

// Adapts TrustCoreIssuer (issueNode/revoke) to the CertificateIssuer port
// EnrollmentService and ThreatResponseService already depend on. Both of
// those were wired to DevelopmentCertificateIssuer — a stub that returns the
// literal string "DEVELOPMENT-ONLY" as the "certificate" — even though
// TrustCoreIssuer/ForgeX509Builder/DevKeyProvider were fully built, tested,
// and never actually connected to anything that issues real certificates at
// runtime. This is the missing wire, not new crypto.
export class TrustCoreCertificateIssuer implements CertificateIssuer {
  constructor(private issuer:TrustCoreIssuer){}
  issueNodeCertificate(nodeId:string,publicKey:string,ttlMinutes:number){
    return this.issuer.issueNode(nodeId,publicKey,ttlMinutes);
  }
  revoke(serial:string,reason:string){
    return this.issuer.revoke(serial,reason);
  }
}
