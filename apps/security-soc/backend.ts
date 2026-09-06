export interface SocData {
  nodes():Promise<unknown[]>;
  incidents():Promise<unknown[]>;
  policies():Promise<unknown[]>;
  jit():Promise<unknown[]>;
  relays():Promise<unknown[]>;
  certificates():Promise<unknown[]>;
  // certificates.revocation_reason (db/002_operational_tables.sql) had no
  // read path anywhere — certificates() itself deliberately excludes
  // revoked rows (WHERE is_revoked=false), and the public CRL endpoint
  // (GET /api/v1/certificates/crl) must never leak this free-text reason to
  // an unauthenticated relying party. This is the one place an operator can
  // actually see why a certificate was revoked.
  revokedCertificates():Promise<unknown[]>;
  events(limit:number):Promise<unknown[]>;
}
export interface SocActions {
  quarantine(nodeId:string,reason:string,actor:string):Promise<void>;
  // clearanceToken is required: a signed BAPC Diagnostics clearance, verified
  // by ThreatResponseService.restore's ClearanceVerifier. The original
  // build-document interface omitted this parameter, which would have let
  // the SOC console restore a quarantined node with no verified forensic
  // clearance at all — corrected here rather than reproduced.
  restore(nodeId:string,actor:string,clearanceToken:string):Promise<void>;
  emergencyLockdown(reason:string,actor:string,confirmation:string):Promise<void>;
}
export class SecuritySocBackend {
  constructor(private data:SocData,private actions:SocActions){}
  async snapshot(){
    const [nodes,incidents,policies,jit,relays,certificates,revokedCertificates,events]=await Promise.all([
      this.data.nodes(),this.data.incidents(),this.data.policies(),this.data.jit(),
      this.data.relays(),this.data.certificates(),this.data.revokedCertificates(),this.data.events(100)
    ]);
    return {generatedAt:new Date(),nodes,incidents,policies,jit,relays,certificates,revokedCertificates,events};
  }
  async quarantine(nodeId:string,reason:string,actor:string){
    if(reason.trim().length<12)throw new Error("quarantine reason must be meaningful");
    await this.actions.quarantine(nodeId,reason,actor);
    return {accepted:true,nodeId};
  }
  async restore(nodeId:string,actor:string,clearanceToken:string){
    await this.actions.restore(nodeId,actor,clearanceToken);
    return {accepted:true,nodeId};
  }
  async emergencyLockdown(reason:string,actor:string,confirmation:string){
    if(confirmation!=="LOCKDOWN")throw new Error("typed LOCKDOWN confirmation required");
    if(reason.trim().length<20)throw new Error("detailed emergency reason required");
    await this.actions.emergencyLockdown(reason,actor,confirmation);
    return {accepted:true,scope:"ecosystem"};
  }
}
