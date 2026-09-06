import {randomUUID} from "node:crypto";

export interface ProtectedKeyProvider {
  sign(keyReference:string,algorithm:"ES256"|"RS256",payload:Buffer):Promise<Buffer>;
  publicKey(keyReference:string):Promise<string>;
}
export interface CertificateRecordStore {
  save(record:{
    id:string;nodeId:string;issuerId:string;serial:string;subject:string;
    issuedAt:Date;expiresAt:Date;revoked:boolean;keyReference:string;
  }):Promise<void>;
  revoke(serial:string,reason:string,at:Date):Promise<void>;
}
export interface X509Builder {
  create(input:{
    serial:string;subject:string;publicKeyPem:string;issuerCertificatePem:string;
    notBefore:Date;notAfter:Date;extensions:Record<string,string>;
    sign:(tbs:Buffer)=>Promise<Buffer>;
  }):Promise<string>;
}
export class TrustCoreIssuer {
  constructor(
    private keys:ProtectedKeyProvider,private records:CertificateRecordStore,
    private x509:X509Builder,private issuer:{
      id:string;certificatePem:string;keyReference:string;algorithm:"ES256"|"RS256";
    }
  ){}
  async issueNode(nodeId:string,nodePublicKeyPem:string,ttlMinutes:number){
    if(ttlMinutes<5||ttlMinutes>1440)throw new Error("certificate TTL outside allowed range");
    const now=new Date(),expiresAt=new Date(now.getTime()+ttlMinutes*60_000);
    const serial=randomUUID().replaceAll("-","");
    const subject=`CN=node:${nodeId},OU=BAPC VPN Digital Security`;
    const certificatePem=await this.x509.create({
      serial,subject,publicKeyPem:nodePublicKeyPem,issuerCertificatePem:this.issuer.certificatePem,
      notBefore:new Date(now.getTime()-60_000),notAfter:expiresAt,
      extensions:{
        basicConstraints:"CA:FALSE",
        keyUsage:"digitalSignature,keyAgreement",
        extendedKeyUsage:"clientAuth,serverAuth",
        subjectAltName:`URI:bapc:security:node:${nodeId}`
      },
      sign:tbs=>this.keys.sign(this.issuer.keyReference,this.issuer.algorithm,tbs)
    });
    await this.records.save({
      id:randomUUID(),nodeId,issuerId:this.issuer.id,serial,subject,
      issuedAt:now,expiresAt,revoked:false,keyReference:"external-node-key"
    });
    return {serial,certificatePem,expiresAt};
  }
  async revoke(serial:string,reason:string){
    if(reason.trim().length<5)throw new Error("revocation reason required");
    await this.records.revoke(serial,reason,new Date());
  }
}
