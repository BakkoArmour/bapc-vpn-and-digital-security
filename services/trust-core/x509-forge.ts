import forge from "node-forge";
import type {X509Builder} from "./issuer.js";

const {pki, asn1} = forge;

const parseDn=(dn:string)=>dn.split(",").map(pair=>{
  const [name,value]=pair.split("=").map(s=>s.trim());
  return {name:name==="CN"?"commonName":name==="OU"?"organizationalUnitName":name!,value:value!};
});

const parseKeyUsage=(csv:string)=>{
  const flags=new Set(csv.split(",").map(s=>s.trim()));
  return {
    name:"keyUsage",
    digitalSignature:flags.has("digitalSignature"),
    keyEncipherment:flags.has("keyEncipherment"),
    keyAgreement:flags.has("keyAgreement"),
    keyCertSign:flags.has("keyCertSign"),
    cRLSign:flags.has("cRLSign")
  };
};
const parseExtKeyUsage=(csv:string)=>{
  const flags=new Set(csv.split(",").map(s=>s.trim()));
  return {name:"extKeyUsage",serverAuth:flags.has("serverAuth"),clientAuth:flags.has("clientAuth")};
};
const parseSubjectAltName=(value:string)=>{
  const [type,name]=value.split(":");
  if(type==="URI")return {name:"subjectAltName",altNames:[{type:6,value:name}]};
  return {name:"subjectAltName",altNames:[{type:2,value:name??value}]};
};

// Builds a real, chain-verifiable X.509 certificate whose signature is produced
// by an EXTERNAL signer callback (never a locally-held private key here) —
// so this class works unmodified whether that signer is dev in-memory RSA
// (see dev-key-provider.ts) or a real HSM/KMS PKCS#11 "sign" operation.
export class ForgeX509Builder implements X509Builder {
  async create(input:{
    serial:string;subject:string;publicKeyPem:string;issuerCertificatePem:string;
    notBefore:Date;notAfter:Date;extensions:Record<string,string>;
    sign:(tbs:Buffer)=>Promise<Buffer>;
  }):Promise<string>{
    const issuerCert=pki.certificateFromPem(input.issuerCertificatePem);
    const cert=pki.createCertificate();
    cert.publicKey=pki.publicKeyFromPem(input.publicKeyPem);
    cert.serialNumber=input.serial;
    cert.validity.notBefore=input.notBefore;
    cert.validity.notAfter=input.notAfter;
    cert.setSubject(parseDn(input.subject));
    cert.setIssuer(issuerCert.subject.attributes);

    const extensions:any[]=[];
    if(input.extensions.basicConstraints){
      extensions.push({name:"basicConstraints",cA:input.extensions.basicConstraints.includes("TRUE")});
    }
    if(input.extensions.keyUsage)extensions.push(parseKeyUsage(input.extensions.keyUsage));
    if(input.extensions.extendedKeyUsage)extensions.push(parseExtKeyUsage(input.extensions.extendedKeyUsage));
    if(input.extensions.subjectAltName)extensions.push(parseSubjectAltName(input.extensions.subjectAltName));
    cert.setExtensions(extensions);

    // Sign: compute the TBS DER, hand only those bytes to the external signer,
    // then splice the returned signature back in — the private key never
    // needs to exist inside this process for a real HSM-backed signer.
    cert.signatureOid=cert.siginfo.algorithmOid=pki.oids["sha256WithRSAEncryption"]!;
    // @types/node-forge omits getTBSCertificate even though it is a public runtime API.
    const tbsCertificate=(pki as any).getTBSCertificate(cert);
    const tbsDer=Buffer.from(asn1.toDer(tbsCertificate).getBytes(),"binary");
    const signature=await input.sign(tbsDer);
    cert.signature=signature.toString("binary");

    return pki.certificateToPem(cert);
  }
}
