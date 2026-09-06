import forge from "node-forge";
import {DevKeyProvider} from "./dev-key-provider.js";
import {ForgeX509Builder} from "./x509-forge.js";

// Convenience for spinning up a throwaway self-signed dev CA (key + cert) —
// used wherever this repo needs "an issuer" to demonstrate a real signing
// pipeline (X.509 issuance, CRL generation) without a production HSM/KMS
// wired up yet. NEVER use in production: see runbooks/root-ca-ceremony.md.
export const createSelfSignedDevCa=async(subjectCn:string,keyReference:string)=>{
  const keys=new DevKeyProvider();
  const publicKeyPem=keys.generate(keyReference,3072);
  const x509=new ForgeX509Builder();
  const placeholder=forge.pki.createCertificate();
  placeholder.publicKey=forge.pki.publicKeyFromPem(publicKeyPem);
  placeholder.setSubject([{name:"commonName",value:subjectCn}]);
  placeholder.validity.notBefore=new Date();
  placeholder.validity.notAfter=new Date(Date.now()+365*86_400_000);
  placeholder.signatureOid=placeholder.siginfo.algorithmOid=forge.pki.oids["sha256WithRSAEncryption"]!;
  placeholder.signature="";
  const placeholderPem=forge.pki.certificateToPem(placeholder);

  const certificatePem=await x509.create({
    serial:"01",subject:`CN=${subjectCn}`,publicKeyPem,issuerCertificatePem:placeholderPem,
    notBefore:new Date(),notAfter:new Date(Date.now()+365*86_400_000),
    extensions:{basicConstraints:"CA:TRUE",keyUsage:"keyCertSign,cRLSign"},
    sign:tbs=>keys.sign(keyReference,"RS256",tbs)
  });
  return {keys,certificatePem,keyReference};
};
